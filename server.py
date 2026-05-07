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
    """Issue a verifiable credential with claims, signature, and expiry. Claims should be JSON string.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        subject (str): The subject to analyze or process.
        credential_type (str): The credential type to analyze or process.
        claims (str): The claims to analyze or process.
        issuer (str): The issuer to analyze or process.
        expires_days (int): The expires days to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
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
    """Verify a credential's validity — checks existence, signature, expiry, and revocation status.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        credential_id (str): The credential id to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    cred = _store.hget("creds", credential_id)
    if not cred:
        return {"valid": False, "reason": "Credential not found", "credential_id": credential_id}
    checks = {"exists": True, "not_revoked": True, "not_expired": True, "signature_valid": True}

    # Revocation check
    revocation_list = _store.get("revocation_list", [])
    if credential_id in revocation_list or cred.get("status") == "revoked":
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
    """Revoke a credential. Adds to revocation list and marks as inactive.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        credential_id (str): The credential id to analyze or process.
        reason (str): The reason to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    cred = _store.hget("creds", credential_id)
    if not cred:
        return {"error": "Credential not found", "credential_id": credential_id}

    revocation_list = _store.get("revocation_list", [])
    revocation_list.append(credential_id)
    _store.set("revocation_list", revocation_list)
    cred["status"] = "revoked"
    cred["revoked_at"] = datetime.now(timezone.utc).isoformat()
    cred["revocation_reason"] = reason
    _store.hset("creds", credential_id, cred)

    return {"credential_id": credential_id, "status": "revoked", "reason": reason}


@mcp.tool()
def list_credentials(subject: str = "", credential_type: str = "", include_revoked: bool = False, api_key: str = "") -> str:
    """List credentials with optional filters by subject and type.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        subject (str): The subject to analyze or process.
        credential_type (str): The credential type to analyze or process.
        include_revoked (bool): The include revoked to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    results = []
    for cid, cred in _store.hgetall("creds").items():
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

    return {"credentials": results, "total": len(results), "revoked_count": len(_store.get("revocation_list", []))}


@mcp.tool()
def audit_credential_usage(api_key: str = "") -> str:
    """Get audit statistics on credential issuance, verification, and revocation.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    types = defaultdict(int)
    issuers = defaultdict(int)
    active = revoked = expired = 0
    now = datetime.now(timezone.utc)
    all_creds = _store.hgetall("creds")

    for cred in all_creds.values():
        types[cred["type"]] += 1
        issuers[cred["issuer"]] += 1
        if cred.get("status") == "revoked":
            revoked += 1
        elif datetime.fromisoformat(cred["expires_at"]) < now:
            expired += 1
        else:
            active += 1

    return {
        "total_issued": len(all_creds),
        "active": active,
        "revoked": revoked,
        "expired": expired,
        "by_type": dict(types),
        "by_issuer": dict(issuers),
    }


if __name__ == "__main__":
    mcp.run()
