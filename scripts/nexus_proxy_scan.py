#!/usr/bin/env python3
"""
Probe an internal Nexus Repository Manager for cached malicious npm packages.

Input:  public/data/malicious-packages.json  (the SSOT)
Output: internal/reports/data/nexus-proxy-scan-result.json

Reads NEXUS_BASE_URL / NEXUS_ID / NEXUS_PW from the project .env. Calls only
read-only REST endpoints (search / search/assets / repositories / status) —
no component is modified, deleted, or invalidated.

Default scope:
- category == "malicious_intent" → name-only probe (any cached version is bad).
- confidence == "suspected" (KISA-listed, no machine-readable advisory) → name-only
  probe; results are segregated under a separate suspected bucket and are
  informational, not high-severity. Disable with --no-suspected.

Pass --include-compromised to also probe the specific malicious versions of
confirmed compromised-legitimate packages (e.g. axios@1.14.1).

Tested against Nexus Repository Manager REST API v1 (Nexus 3.70.4-02).

Usage:
  python3 scripts/nexus_proxy_scan.py
  python3 scripts/nexus_proxy_scan.py --dry-run
  python3 scripts/nexus_proxy_scan.py --include-compromised
  python3 scripts/nexus_proxy_scan.py --no-suspected
  python3 scripts/nexus_proxy_scan.py --repo npm-proxy --repo npm-group
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
INDEX_PATH = ROOT_DIR / "public" / "data" / "malicious-packages.json"
REPORTS_DATA_DIR = ROOT_DIR / "internal" / "reports" / "data"
OUTPUT_JSON = REPORTS_DATA_DIR / "nexus-proxy-scan-result.json"

REQUEST_TIMEOUT = 15  # seconds per HTTP call


# ── env loading (shared pattern) ──────────────────────────────────────────────

def load_env(path: str | Path = ROOT_DIR / ".env") -> None:
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())


load_env()

NEXUS_BASE_URL = os.environ.get("NEXUS_BASE_URL", "").strip().rstrip("/")
NEXUS_ID = os.environ.get("NEXUS_ID", "").strip()
NEXUS_PW = os.environ.get("NEXUS_PW", "").strip()

# Some internal Nexus deployments terminate TLS with self-signed certs;
# mirror the SSL-relaxed style already used by canisterworm_analysis.py.
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# Maps SSOT ecosystem names → Nexus repository format strings.
# Only ecosystems listed here are scanned; others are silently skipped.
ECOSYSTEM_TO_NEXUS_FORMAT: dict[str, str] = {
    "npm": "npm",
    "PyPI": "pypi",
    "Maven": "maven2",
    "crates.io": "cargo",
    "Go": "go",
    "NuGet": "nuget",
}


def _basic_auth_header(user: str, pw: str) -> str:
    return "Basic " + b64encode(f"{user}:{pw}".encode()).decode()


def http_get(url: str, auth_header: str | None = None,
             timeout: int = REQUEST_TIMEOUT,
             retries: int = 2,
             backoff: float = 0.5) -> tuple[int, bytes]:
    """GET with retry on transient 5xx / transport errors.

    Returns (status_code, body_bytes). The Nexus search backend occasionally
    returns 500 under concurrent load (Elasticsearch hiccups); a single retry
    almost always succeeds.
    """
    last_code = 0
    last_body = b""
    for attempt in range(retries + 1):
        req = urllib.request.Request(url)
        if auth_header:
            req.add_header("Authorization", auth_header)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "PoisonChain/nexus_proxy_scan")
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            last_code = e.code
            last_body = e.read() if hasattr(e, "read") else b""
            if 500 <= e.code < 600 and attempt < retries:
                time.sleep(backoff * (attempt + 1))
                continue
            return last_code, last_body
        except (urllib.error.URLError, TimeoutError) as e:
            last_code = 0
            last_body = str(e).encode()
            if attempt < retries:
                time.sleep(backoff * (attempt + 1))
                continue
            return last_code, last_body
    return last_code, last_body


# ── SSOT loader ───────────────────────────────────────────────────────────────

def load_index() -> dict:
    if not INDEX_PATH.exists():
        sys.exit(f"ERROR: {INDEX_PATH} not found. Run "
                 f"`python3 scripts/build_malicious_package_index.py --validate` first.")
    return json.loads(INDEX_PATH.read_text())


def load_targets(index: dict, include_compromised: bool,
                 include_suspected: bool = True) -> list[dict]:
    """Return list of {name, version, category, confidence, campaign, known_hashes}.

    For category=='malicious_intent': probe every listed version, AND a
    bare-name probe (version=None) so we catch unknown versions of a package
    that should not exist in our registry at all.

    For category=='compromised_legitimate' + confidence=='confirmed': only
    probe specific malicious versions (and only when --include-compromised is
    set), because the legitimate versions of these packages are in routine use.

    For confidence=='suspected': name-only probe regardless of category. The
    KISA-listed entry stores no specific malicious version, so a version probe
    is impossible; the name probe is the only available signal. Results land
    in a segregated bucket so they never escalate to high-severity.
    """
    out: list[dict] = []
    for p in index.get("packages", []):
        ecosystem = p.get("ecosystem", "npm")
        if ecosystem not in ECOSYSTEM_TO_NEXUS_FORMAT:
            continue  # unsupported ecosystem — skip silently
        category = p.get("category")
        confidence = p.get("confidence", "confirmed")
        name = p["name"]
        versions = p.get("malicious_versions") or []
        known_hashes = p.get("known_hashes") or {}
        campaign = p.get("campaign")
        npm_status = p.get("npm_status") if ecosystem == "npm" else None

        if confidence == "suspected":
            if not include_suspected:
                continue
            out.append(_target(name, None, category, campaign, None,
                               confidence="suspected", npm_status=npm_status,
                               ecosystem=ecosystem))
            continue

        if category == "malicious_intent":
            out.append(_target(name, None, category, campaign, None,
                               confidence="confirmed", ecosystem=ecosystem))
        elif category == "compromised_legitimate":
            if not include_compromised:
                continue
            for ver in versions:
                out.append(_target(name, ver, category, campaign,
                                   known_hashes.get(ver), confidence="confirmed",
                                   ecosystem=ecosystem))
        # else: skip 'unknown' category
    return out


def _target(name: str, version: str | None, category: str, campaign: str | None,
            known_hashes: dict | None, confidence: str = "confirmed",
            npm_status: str | None = None, ecosystem: str = "npm") -> dict:
    sans_sha1 = None
    sans_sha256 = None
    if known_hashes:
        sans_sha1 = known_hashes.get("sha1_sans") or (
            known_hashes.get("sha1") if known_hashes.get("source") == "SANS" else None
        )
        sans_sha256 = known_hashes.get("sha256_sans") or (
            known_hashes.get("sha256") if known_hashes.get("source") == "SANS" else None
        )
    return {
        "name": name,
        "ecosystem": ecosystem,
        "version": version,
        "category": category,
        "campaign": campaign,
        "confidence": confidence,
        "npm_status": npm_status,
        "sans_sha1": sans_sha1,
        "sans_sha256": sans_sha256,
    }


# ── Nexus API wrappers ────────────────────────────────────────────────────────

def list_npm_repositories(base_url: str, auth: str) -> tuple[list[str], str | None]:
    """GET /service/rest/v1/repositories. Returns (npm_repo_names, error_or_None)."""
    url = f"{base_url}/service/rest/v1/repositories"
    code, body = http_get(url, auth_header=auth)
    if code != 200:
        return [], f"GET {url} → HTTP {code}"
    try:
        repos = json.loads(body)
    except Exception as e:
        return [], f"GET {url} → not JSON: {e}"
    names: list[str] = []
    for r in repos:
        if (r.get("format") or "").lower() == "npm":
            names.append(r.get("name", ""))
    return [n for n in names if n], None


def list_repositories_by_format(base_url: str, auth: str) -> tuple[dict[str, list[str]], str | None]:
    """GET /service/rest/v1/repositories. Returns ({format: [repo_names]}, error).

    Only returns formats that appear in ECOSYSTEM_TO_NEXUS_FORMAT values.
    """
    url = f"{base_url}/service/rest/v1/repositories"
    code, body = http_get(url, auth_header=auth)
    if code != 200:
        return {}, f"GET {url} → HTTP {code}"
    try:
        repos = json.loads(body)
    except Exception as e:
        return {}, f"GET {url} → not JSON: {e}"
    known_formats = set(ECOSYSTEM_TO_NEXUS_FORMAT.values())
    result: dict[str, list[str]] = {}
    for r in repos:
        fmt = (r.get("format") or "").lower()
        if fmt in {f.lower() for f in known_formats}:
            result.setdefault(fmt, []).append(r.get("name", ""))
    return {k: [n for n in v if n] for k, v in result.items()}, None


def _parse_maven_coords(name: str) -> tuple[str, str]:
    """Split 'groupId:artifactId' → (groupId, artifactId).

    OSV Maven advisories use 'groupId:artifactId' as the package name.
    """
    if ":" in name:
        g, a = name.split(":", 1)
        return g, a
    return "", name


def search_component(base_url: str, repo: str, name: str,
                     version: str | None, auth: str) -> tuple[list[dict], str | None]:
    """GET /service/rest/v1/search?repository=&format=npm&name=&version=

    Returns (items, error).  items is a list of {id, version, name, ...} dicts.
    """
    params = {
        "repository": repo,
        "format": "npm",
        "name": name,
    }
    if version:
        params["version"] = version
    url = f"{base_url}/service/rest/v1/search?" + urllib.parse.urlencode(params)
    code, body = http_get(url, auth_header=auth)
    if code != 200:
        return [], f"HTTP {code}"
    try:
        return json.loads(body).get("items", []), None
    except Exception as e:
        return [], f"not JSON: {e}"


def search_assets(base_url: str, repo: str, name: str,
                  version: str | None, auth: str) -> tuple[list[dict], str | None]:
    """GET /service/rest/v1/search/assets — richer per-asset info (checksums etc.)"""
    params = {
        "repository": repo,
        "format": "npm",
        "name": name,
    }
    if version:
        params["version"] = version
    url = f"{base_url}/service/rest/v1/search/assets?" + urllib.parse.urlencode(params)
    code, body = http_get(url, auth_header=auth)
    if code != 200:
        return [], f"HTTP {code}"
    try:
        return json.loads(body).get("items", []), None
    except Exception as e:
        return [], f"not JSON: {e}"


def _split_npm_name(canonical: str) -> tuple[str, str]:
    """Return (scope_without_leading_at, short_name) for a canonical npm name.

    For unscoped: ('', name).  For scoped: ('scope', 'pkg').
    """
    if canonical.startswith("@") and "/" in canonical:
        scope, short = canonical[1:].split("/", 1)
        return scope, short
    return "", canonical


def _item_matches(item: dict, target_name: str) -> bool:
    """Return True if a Nexus search result is for the *same* npm package.

    Nexus indexes npm packages by separate 'name' (short) and 'group' (scope)
    fields, and treats the URL ?name=X param as a short-name match. So a query
    for 'auth-types' will also surface '@firebase/auth-types'. We compare
    semantically: an unscoped target only matches an unscoped result, and a
    scoped target only matches a result with the matching scope.
    """
    target_scope, target_short = _split_npm_name(target_name)
    item_short = item.get("name") or ""
    item_group = item.get("group") or ""
    return item_short == target_short and item_group == target_scope


def search_all_repos(base_url: str, name: str, version: str | None,
                     auth: str) -> tuple[list[dict], str | None]:
    """GET /service/rest/v1/search?format=npm&name=... (no repository filter).

    Returns all components matching the name (and optionally version) across
    every npm-format repository. The Nexus API matches on short-name only, so
    we filter the response client-side via _item_matches() to drop scoped
    packages that share the short name.
    """
    items: list[dict] = []
    _, short = _split_npm_name(name)
    base_params = {"format": "npm", "name": short}
    if version:
        base_params["version"] = version

    next_token: str | None = None
    for _ in range(20):  # safety bound on pagination
        params = dict(base_params)
        if next_token:
            params["continuationToken"] = next_token
        url = f"{base_url}/service/rest/v1/search?" + urllib.parse.urlencode(params)
        code, body = http_get(url, auth_header=auth)
        if code != 200:
            return items, f"HTTP {code}"
        try:
            data = json.loads(body)
        except Exception as e:
            return items, f"not JSON: {e}"
        # Filter to true matches (drop scope-suffix collisions)
        for it in data.get("items", []):
            if _item_matches(it, name):
                items.append(it)
        next_token = data.get("continuationToken")
        if not next_token:
            break
    return items, None


def search_all_repos_generic(
    base_url: str, ecosystem: str, name: str, version: str | None, auth: str
) -> tuple[list[dict], str | None]:
    """Search Nexus for *name* (and optionally *version*) across all repos for *ecosystem*.

    Routes to the npm-specific logic (with scope/group matching) for npm, and
    uses a direct format-parameterised search for all other ecosystems.
    Maven packages use 'groupId:artifactId' in the SSOT; these are split into
    separate maven.groupId / maven.artifactId query params for Nexus.
    """
    if ecosystem == "npm":
        return search_all_repos(base_url, name, version, auth)

    nexus_fmt = ECOSYSTEM_TO_NEXUS_FORMAT.get(ecosystem, ecosystem.lower())

    if ecosystem == "Maven":
        group_id, artifact_id = _parse_maven_coords(name)
        base_params: dict[str, str] = {"format": nexus_fmt}
        if group_id:
            base_params["maven.groupId"] = group_id
        if artifact_id:
            base_params["maven.artifactId"] = artifact_id
    else:
        base_params = {"format": nexus_fmt, "name": name}

    if version:
        base_params["version"] = version

    items: list[dict] = []
    next_token: str | None = None
    for _ in range(20):
        params = dict(base_params)
        if next_token:
            params["continuationToken"] = next_token
        url = f"{base_url}/service/rest/v1/search?" + urllib.parse.urlencode(params)
        code, body = http_get(url, auth_header=auth)
        if code != 200:
            return items, f"HTTP {code}"
        try:
            data = json.loads(body)
        except Exception as e:
            return items, f"not JSON: {e}"
        for it in data.get("items", []):
            if ecosystem == "Maven":
                # Nexus returns groupId in 'group', artifactId in 'name'
                full = f"{it.get('group', '')}:{it.get('name', '')}"
                if full != name:
                    continue
            else:
                if it.get("name") != name:
                    continue
            items.append(it)
        next_token = data.get("continuationToken")
        if not next_token:
            break
    return items, None


# ── Risk model ────────────────────────────────────────────────────────────────

def compute_risk(category: str, found: bool, sha_match: bool | None,
                 confidence: str = "confirmed") -> str:
    if not found:
        return "LOW"
    # confidence == 'suspected' caps the risk at INFO because the SSOT entry
    # itself is a recall-first inclusion (KISA-listed, no machine-readable
    # advisory). Surface it for review, do not page on it.
    if confidence == "suspected":
        return "INFO"
    if category == "malicious_intent":
        return "CRITICAL" if sha_match else "HIGH"
    if category == "compromised_legitimate":
        return "CRITICAL" if sha_match else "MEDIUM"
    return "LOW"


# ── Scan ──────────────────────────────────────────────────────────────────────

def scan_target(base_url: str, auth: str, target: dict) -> tuple[list[dict], str | None]:
    """Run a single (name, version) probe across all repos for the target's ecosystem.

    Returns (rows, error_or_None). rows is a list of result entries — one per
    (repository, version) hit. Empty rows means 'package not found in any
    repository'. We surface a miss row separately at the caller so summary
    counts stay consistent.
    """
    ecosystem = target.get("ecosystem", "npm")
    items, err = search_all_repos_generic(base_url, ecosystem, target["name"], target["version"], auth)
    if err:
        return [], err

    if not items:
        return [], None

    rows: list[dict] = []
    for it in items:
        # /v1/search embeds assets[] on each component for npm — so we get
        # checksum / lastDownloaded / blob_created without a second request.
        asset = (it.get("assets") or [None])[0] or {}
        cks = asset.get("checksum") or {}
        entry = {
            "package": target["name"],
            "ecosystem": ecosystem,
            "version_queried": target["version"],
            "version_found": it.get("version"),
            "category": target["category"],
            "campaign": target["campaign"],
            "repository": it.get("repository"),
            "found_in_cache": True,
            "asset_sha1": cks.get("sha1"),
            "asset_sha256": cks.get("sha256"),
            "asset_sha512": cks.get("sha512"),
            "blob_created": asset.get("blobCreated"),
            "last_downloaded": asset.get("lastDownloaded"),
            "last_modified": asset.get("lastModified"),
            "file_size": asset.get("fileSize"),
            "path": asset.get("path"),
            "uploader": asset.get("uploader"),
            "uploader_ip": asset.get("uploaderIp"),
        }
        sha_match = _checksum_match(entry, target)
        entry["asset_sha_matches_ioc"] = sha_match
        entry["risk_level"] = compute_risk(
            target["category"], True, sha_match,
            confidence=target.get("confidence", "confirmed"),
        )
        rows.append(entry)
    return rows, None


def scan(base_url: str, auth: str, targets: list[dict],
         max_workers: int = 12,
         progress_every: int = 500) -> tuple[list[dict], list[str], list[dict]]:
    """Parallel scan. Returns (results, partial_reasons, errors).

    results contains BOTH hits and misses (one miss row per target with
    found_in_cache=False) so summary counts remain meaningful.
    """
    results: list[dict] = []
    errors: list[dict] = []
    reasons: list[str] = []

    start = time.monotonic()
    completed = 0
    hits = 0
    total = len(targets)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_target, base_url, auth, t): t for t in targets}
        for fut in as_completed(futures):
            t = futures[fut]
            completed += 1
            try:
                rows, err = fut.result()
            except Exception as exc:
                errors.append({
                    "package": t["name"], "version": t["version"],
                    "error": f"exception: {exc}",
                })
                continue

            if err:
                errors.append({
                    "package": t["name"], "version": t["version"], "error": err,
                })
                # Still record a miss row so totals add up
                results.append({
                    "package": t["name"], "version_queried": t["version"],
                    "category": t["category"], "campaign": t["campaign"],
                    "confidence": t.get("confidence", "confirmed"),
                    "found_in_cache": False, "risk_level": "LOW",
                    "search_error": err,
                })
                continue

            if not rows:
                results.append({
                    "package": t["name"], "version_queried": t["version"],
                    "category": t["category"], "campaign": t["campaign"],
                    "confidence": t.get("confidence", "confirmed"),
                    "found_in_cache": False, "risk_level": "LOW",
                })
            else:
                for r in rows:
                    r["confidence"] = t.get("confidence", "confirmed")
                results.extend(rows)
                hits += len(rows)

            if progress_every and completed % progress_every == 0:
                elapsed = time.monotonic() - start
                rate = completed / elapsed if elapsed else 0
                eta = (total - completed) / rate if rate else 0
                _render_progress(completed, total, rate, hits, eta)

    auth_failures = sum(1 for e in errors if "401" in str(e.get("error", ""))
                        or "403" in str(e.get("error", "")))
    if auth_failures:
        reasons.append(f"auth failure on {auth_failures} request(s)")

    elapsed = time.monotonic() - start
    if progress_every:
        # Clear the in-place progress line before printing the final summary
        # so the "done in ..." line is not visually concatenated to it.
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
    print(f"  done in {elapsed:.1f}s "
          f"({completed} targets, {len(errors)} errors, {hits} hit rows)")
    return results, reasons, errors


def _render_progress(completed: int, total: int, rate: float,
                     hits: int, eta: float) -> None:
    """Render a single-line in-place progress update.

    Uses a carriage return plus ANSI erase-to-end-of-line so the line is
    overwritten in the terminal instead of producing one row of output per
    progress tick. Falls back to a plain print when stdout is not a tty
    (CI logs, piped output) so log files retain a readable history.
    """
    bar_width = 24
    filled = int(bar_width * completed / total) if total else 0
    bar = "█" * filled + "░" * (bar_width - filled)
    pct = (100 * completed / total) if total else 0
    msg = (f"  [{bar}] {pct:5.1f}%  {completed}/{total}  "
           f"{rate:.0f}/s  hits={hits}  eta {eta:.0f}s")
    if sys.stdout.isatty():
        sys.stdout.write("\r\033[K" + msg)
        sys.stdout.flush()
    else:
        print(msg, flush=True)


def _checksum_match(entry: dict, target: dict) -> bool | None:
    """Compare asset checksums to SANS-published reference hashes.

    Returns:
      True  — at least one (sha1 or sha256) matches the known IOC hash
      False — IOC hash exists but doesn't match (different build / repack)
      None  — no IOC hash on file to compare against (e.g. campaign-targeted
              package without published per-version hash)
    """
    sans_sha1 = target.get("sans_sha1")
    sans_sha256 = target.get("sans_sha256")
    asset_sha1 = entry.get("asset_sha1")
    asset_sha256 = entry.get("asset_sha256")

    if not (sans_sha1 or sans_sha256):
        return None
    if sans_sha1 and asset_sha1 and sans_sha1.lower() == asset_sha1.lower():
        return True
    if sans_sha256 and asset_sha256 and sans_sha256.lower() == asset_sha256.lower():
        return True
    return False


# ── Summary ───────────────────────────────────────────────────────────────────

def build_summary(results: list[dict]) -> dict:
    by_cat: dict[str, dict] = {}
    by_confidence: dict[str, dict] = {}
    risk_counts: dict[str, int] = {}
    hits = 0
    suspected_hits = 0
    for r in results:
        c = r["category"] or "unknown"
        conf = r.get("confidence", "confirmed")
        by_cat.setdefault(c, {"queried": 0, "hits": 0})
        by_cat[c]["queried"] += 1
        by_confidence.setdefault(conf, {"queried": 0, "hits": 0})
        by_confidence[conf]["queried"] += 1
        if r["found_in_cache"]:
            by_cat[c]["hits"] += 1
            by_confidence[conf]["hits"] += 1
            hits += 1
            if conf == "suspected":
                suspected_hits += 1
        risk_counts[r["risk_level"]] = risk_counts.get(r["risk_level"], 0) + 1
    return {
        "hits_total": hits,
        "hits_confirmed": hits - suspected_hits,
        "hits_suspected": suspected_hits,
        "by_category": by_cat,
        "by_confidence": by_confidence,
        "risk_counts": risk_counts,
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print intended scope and exit without contacting Nexus.",
    )
    parser.add_argument(
        "--include-compromised", action="store_true",
        help="Also probe specific malicious versions of compromised_legitimate "
             "packages (e.g. axios@1.14.1). Default: malicious_intent only.",
    )
    parser.add_argument(
        "--no-suspected", action="store_true",
        help="Skip confidence: suspected (KISA-listed) entries. Default: include "
             "them with a name-only probe; results are segregated under a "
             "suspected bucket and are informational.",
    )
    parser.add_argument(
        "--repo", action="append", default=[],
        help="Limit scan to specific repository name(s); repeatable. "
             "Default: auto-detect all npm-format repositories.",
    )
    parser.add_argument(
        "--probe", action="append", default=[],
        help="Ad-hoc probe target: 'name' or 'name@version'. Treated as "
             "malicious_intent. Repeatable. For one-off tests outside the SSOT.",
    )
    parser.add_argument(
        "--workers", type=int, default=12,
        help="Parallel HTTP workers against Nexus. Default 12. Increase if "
             "Nexus tolerates more, decrease if you see throttling.",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Cap the number of targets scanned (debug/smoke test).",
    )
    args = parser.parse_args()

    if not NEXUS_BASE_URL or not NEXUS_ID or not NEXUS_PW:
        sys.exit("ERROR: NEXUS_BASE_URL / NEXUS_ID / NEXUS_PW must be set in .env")

    index = load_index()
    targets = load_targets(
        index,
        include_compromised=args.include_compromised,
        include_suspected=not args.no_suspected,
    )
    probes: list[dict] = []
    for spec in args.probe:
        if "@" in spec.lstrip("@"):  # handle scoped names like @scope/name@1.2.3
            head, _, ver = spec.rpartition("@")
            if head and ver and not ver.startswith("/"):
                probes.append(_target(head, ver, "malicious_intent", "probe", None))
                continue
        probes.append(_target(spec, None, "malicious_intent", "probe", None))
    auth = _basic_auth_header(NEXUS_ID, NEXUS_PW)

    filters = ["malicious_intent"]
    if args.include_compromised:
        filters.append("compromised_legitimate")
    if not args.no_suspected:
        filters.append("suspected")

    suspected_count = sum(1 for t in targets if t.get("confidence") == "suspected")
    eco_counts = {}
    for t in targets:
        eco_counts[t.get("ecosystem", "npm")] = eco_counts.get(t.get("ecosystem", "npm"), 0) + 1
    eco_summary = ", ".join(f"{eco}:{cnt}" for eco, cnt in sorted(eco_counts.items()))
    print(f"📦 Nexus: {NEXUS_BASE_URL}")
    print(f"📋 SSOT:  {INDEX_PATH.relative_to(ROOT_DIR)}")
    print(f"🎯 Targets: {len(targets)} "
          f"({len(targets) - suspected_count} confirmed + {suspected_count} suspected) "
          f"[filter: {' + '.join(filters)}] [{eco_summary}]")

    partial_reasons: list[str] = []
    errors: list[dict] = []

    # Resolve repository inventory — for reporting only; actual search runs
    # without a repository filter (one call covers all format repos).
    if args.repo:
        repos = list(args.repo)
        print(f"📚 Repositories (reported, --repo override): {repos}")
    elif args.dry_run:
        print("📚 Repositories: (would auto-detect via GET /v1/repositories)")
        repos = []
    else:
        repos_by_fmt, err = list_repositories_by_format(NEXUS_BASE_URL, auth)
        if err:
            sys.exit(f"ERROR: cannot list repositories: {err}")
        if not repos_by_fmt:
            sys.exit("ERROR: no supported-format repositories found")
        repos = [r for rlist in repos_by_fmt.values() for r in rlist]
        for fmt, rlist in sorted(repos_by_fmt.items()):
            print(f"📚 {fmt} repositories: {len(rlist)} "
                  f"({', '.join(rlist[:3])}{'...' if len(rlist) > 3 else ''})")

    if args.limit:
        targets = targets[: args.limit]
        print(f"⚠️  --limit {args.limit} active — first {len(targets)} SSOT "
              f"target(s) (probes are not affected)")
    # Probes are always included — they're explicit user-requested checks.
    targets = targets + probes
    if probes:
        print(f"🧪 + {len(probes)} probe target(s) appended")

    if args.dry_run:
        print(f"\n[dry-run] would query {len(targets)} targets via global search "
              f"(1 call per target, no repository filter)")
        for t in targets[:10]:
            print(f"  - {t['name']} @ {t['version'] or '*'} "
                  f"({t['category']}, {t['campaign']})")
        if len(targets) > 10:
            print(f"  ... and {len(targets) - 10} more")
        return 0

    # Status probe
    code, _ = http_get(f"{NEXUS_BASE_URL}/service/rest/v1/status", auth_header=auth)
    if code not in (200, 204):
        partial_reasons.append(f"/v1/status returned HTTP {code}")
        print(f"⚠️  Nexus status endpoint returned HTTP {code}")

    print(f"\n🔍 Scanning {len(targets)} targets with {args.workers} workers...")
    results, scan_reasons, scan_errors = scan(
        NEXUS_BASE_URL, auth, targets, max_workers=args.workers,
    )
    partial_reasons.extend(scan_reasons)
    errors.extend(scan_errors)

    summary = build_summary(results)

    output = {
        "scan_time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_index": str(INDEX_PATH.relative_to(ROOT_DIR)),
        "nexus_base_url": NEXUS_BASE_URL,
        "repositories_scanned": repos,
        "include_compromised": args.include_compromised,
        "partial_scan": bool(partial_reasons),
        "partial_scan_reasons": list(dict.fromkeys(partial_reasons)),
        "packages_queried": len(targets),
        "hits_total": summary["hits_total"],
        "summary": summary,
        "results": results,
        "errors": errors,
    }

    REPORTS_DATA_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")

    print(f"\n📄 Result: {OUTPUT_JSON.relative_to(ROOT_DIR)}")
    print(f"   Targets probed: {len(targets)} (one global-search call each)")
    print(f"   Hit rows: {summary['hits_total']}  "
          f"(confirmed={summary['hits_confirmed']} suspected={summary['hits_suspected']}, "
          f"a target may hit in >1 repo)")
    print(f"   Risk: {summary['risk_counts']}")
    hot = [r for r in results if r["risk_level"] in ("CRITICAL", "HIGH")]
    if hot:
        print(f"\n🚨 {len(hot)} CRITICAL/HIGH row(s) — inspect the JSON:")
        for r in hot[:10]:
            ver = r.get("version_found") or r.get("version_queried") or "*"
            print(f"   - [{r['risk_level']}] {r['repository']} :: "
                  f"{r['package']}@{ver}"
                  f"  (last_downloaded={r.get('last_downloaded')})")
        if len(hot) > 10:
            print(f"   ... and {len(hot) - 10} more")
    suspected_hits = [r for r in results
                      if r["found_in_cache"] and r.get("confidence") == "suspected"]
    if suspected_hits:
        print(f"\n🟡 {len(suspected_hits)} suspected hit(s) "
              f"(KISA-listed, OSV/postmortem 미확정 — 검토 필요):")
        for r in suspected_hits[:10]:
            ver = r.get("version_found") or r.get("version_queried") or "*"
            print(f"   - {r['repository']} :: {r['package']}@{ver}")
        if len(suspected_hits) > 10:
            print(f"   ... and {len(suspected_hits) - 10} more")
    if partial_reasons:
        print("   Partial scan:", "; ".join(partial_reasons))

    return 0


if __name__ == "__main__":
    sys.exit(main())
