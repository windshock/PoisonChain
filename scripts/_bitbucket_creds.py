"""Bitbucket access helper.

Replaces the legacy XEIZE ``/open-api/v1/git/credentials`` path that has been
removed from the current XEIZE OpenAPI spec (``api-1.0.0-oas-3.1.0.yaml``).
Older deployments still serve the endpoint but reject calls at the gateway
layer with an empty-body 401, so the practical answer is the same: callers
need a Bitbucket PAT directly.

Recommended ``.env`` setup::

    BITBUCKET_PAT=<personal-access-token>      # required
    BITBUCKET_BASE_URL=https://bitbucket.example.com  # optional, default shown

Scripts that previously called a private ``get_pat()`` against XEIZE should
import :func:`get_bitbucket_pat` and :func:`get_bitbucket_base_url` from this
module instead. The XEIZE call is still attempted as a backward-compat
fallback, but the recommended path is the direct PAT.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.request

DEFAULT_BB_BASE = "https://bitbucket.example.com"

_PAT_CACHE: str | None = None


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def get_bitbucket_base_url() -> str:
    """Return the configured Bitbucket Server base URL (no trailing slash)."""
    return os.environ.get("BITBUCKET_BASE_URL", DEFAULT_BB_BASE).rstrip("/")


def _try_xeize_legacy() -> str | None:
    """Best-effort attempt at the deprecated XEIZE PAT distribution endpoint.

    Returns ``None`` when the path is unreachable (e.g. 401 from the gateway,
    or the endpoint was removed entirely). Errors are swallowed because the
    direct-PAT path is the recommended replacement and the caller surfaces a
    single actionable message either way.
    """
    api_key = os.environ.get("XEIZE_API_KEY", "").strip()
    base_url = os.environ.get("XEIZE_BASE_URL", "").strip().rstrip("/")
    if not api_key or not base_url:
        return None
    try:
        req = urllib.request.Request(
            f"{base_url}/projects",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        with urllib.request.urlopen(req, context=_ssl_ctx()) as r:
            projects = json.loads(r.read())
    except Exception:
        return None
    for p in projects:
        if not p.get("integrationId"):
            continue
        try:
            req2 = urllib.request.Request(
                f"{base_url}/git/credentials?project_id={p['id']}",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            with urllib.request.urlopen(req2, context=_ssl_ctx()) as r2:
                creds = json.loads(r2.read())
        except Exception:
            continue
        pat = creds.get("personalAccessToken")
        if pat:
            return pat
    return None


def get_bitbucket_pat() -> str:
    """Return a Bitbucket PAT, or exit the process with a helpful message.

    Lookup order:

    1. ``BITBUCKET_PAT`` environment variable (recommended).
    2. Legacy XEIZE ``/git/credentials`` endpoint, for backward compatibility
       with deployments that still expose it.

    If neither path yields a token, ``sys.exit`` fires with instructions for
    minting a PAT manually. Result is cached for the process lifetime so
    subsequent calls do not re-probe XEIZE.
    """
    global _PAT_CACHE
    if _PAT_CACHE:
        return _PAT_CACHE

    direct = os.environ.get("BITBUCKET_PAT", "").strip()
    if direct:
        _PAT_CACHE = direct
        return direct

    legacy = _try_xeize_legacy()
    if legacy:
        _PAT_CACHE = legacy
        return legacy

    bb = get_bitbucket_base_url()
    sys.exit(
        "ERROR: Could not obtain a Bitbucket PAT.\n"
        "  Set BITBUCKET_PAT in your .env file with a token minted at:\n"
        f"    {bb} → Profile → Manage account → Personal access tokens\n"
        "  Minimum scope: Repository read.\n"
        "  The legacy XEIZE /open-api/v1/git/credentials path was also tried\n"
        "  and rejected — that endpoint has been removed from the current\n"
        "  XEIZE OpenAPI spec (api-1.0.0-oas-3.1.0.yaml)."
    )


def get_git_credentials_for_project(project_id: str) -> dict | None:
    """Compatibility shim for callers that previously expected the XEIZE
    per-project response shape ``{"gitUrl": ..., "personalAccessToken": ...}``.

    With direct PAT auth the same token works for every repository on the
    Bitbucket Server, so the per-project gitUrl is derived from the configured
    base URL. The function returns ``None`` only if no PAT is available — in
    which case ``get_bitbucket_pat()`` would have already exited the process,
    so callers can treat a non-None result as fully populated.
    """
    pat = get_bitbucket_pat()
    return {
        "gitUrl": get_bitbucket_base_url(),
        "personalAccessToken": pat,
    }
