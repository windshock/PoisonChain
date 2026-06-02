#!/usr/bin/env python3
"""
Supplement public/data/malicious-packages.json from machine-readable advisories.

This script intentionally complements, rather than replaces,
scripts/build_malicious_package_index.py:

- Datadog remains the broad sample-dataset source.
- OSV/GHSA is used for advisory-backed package/version corrections, especially
  when secondary reports list package names that differ from canonical npm names.
- Human-readable reports such as JFrog/KISA/TanStack postmortems are tracked in
  public/data/supplemental-malicious-package-sources.json for review context, but
  machine-readable feeds are preferred for automated merges.

Usage:
    python3 scripts/supplement_malicious_package_index.py --dry-run
    python3 scripts/supplement_malicious_package_index.py --write
    python3 scripts/supplement_malicious_package_index.py --advisory GHSA-g7cv-rxg3-hmpx --write
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
INDEX_PATH = ROOT_DIR / "public" / "data" / "malicious-packages.json"
SUPPLEMENT_PATH = ROOT_DIR / "public" / "data" / "supplemental-malicious-package-sources.json"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
OSV_GCS_BASE = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
OSV_MODIFIED_CSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/modified_id.csv"
OSV_SINGLE_VULN_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/{id}.json"
# Ecosystems to scan for malicious packages from the OSV GCS bulk bundle.
# Keys are the OSV ecosystem identifiers (used in the bundle URL and advisory JSON).
OSV_BULK_ECOSYSTEMS: dict[str, str] = {
    "npm": "npm",
    "PyPI": "PyPI",
    "Maven": "Maven",
    "crates.io": "crates.io",
    "Go": "Go",
    "NuGet": "NuGet",
}



class SupplementError(RuntimeError):
    pass


def load_env(path: Path = ROOT_DIR / ".env") -> None:
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SupplementError(f"file not found: {path}")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SupplementError(f"invalid JSON in {path}: {exc}") from exc


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def fetch_json(url: str) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "PoisonChain/supplement_malicious_package_index",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise SupplementError(f"HTTP {exc.code} while fetching {url}") from exc
    except urllib.error.URLError as exc:
        raise SupplementError(f"network error while fetching {url}: {exc}") from exc


def fetch_osv_advisory(advisory_id: str) -> dict[str, Any]:
    encoded = urllib.parse.quote(advisory_id, safe="")
    return fetch_json(OSV_VULN_URL.format(id=encoded))


def normalize_ecosystem(value: str | None) -> str:
    """Normalise an OSV ecosystem string to the canonical form used in the SSOT."""
    if not value:
        return ""
    aliases: dict[str, str] = {
        "npm": "npm",
        "pypi": "PyPI",
        "maven": "Maven",
        "crates.io": "crates.io",
        "go": "Go",
        "nuget": "NuGet",
    }
    return aliases.get(value.lower(), value)


def affected_packages(osv: dict[str, Any], ecosystem_filter: str | None = None) -> list[dict[str, Any]]:
    """Extract canonical package/version rows from one OSV advisory.

    If ``ecosystem_filter`` is given (e.g. ``"npm"``), only entries matching
    that ecosystem are returned.  Otherwise all ecosystems are included.
    """
    rows: list[dict[str, Any]] = []
    for affected in osv.get("affected", []) or []:
        package = affected.get("package") or {}
        ecosystem = normalize_ecosystem(package.get("ecosystem"))
        name = package.get("name")
        if not ecosystem or not name:
            continue
        if ecosystem_filter and ecosystem != normalize_ecosystem(ecosystem_filter):
            continue

        versions = sorted(set(affected.get("versions") or []))
        ranges = affected.get("ranges") or []
        rows.append(
            {
                "ecosystem": ecosystem,
                "name": name,
                "versions": versions,
                "ranges": ranges,
            }
        )
    return rows


def ensure_campaigns(index: dict[str, Any], supplements: dict[str, Any]) -> None:
    """Merge supplemental campaign metadata into the SSOT.

    - Brand-new campaigns are copied in wholesale.
    - For campaigns the SSOT already knows about, only fields that are not
      already present are added — existing values (e.g. hand-edited notes)
      are preserved. This keeps newly-introduced metadata (like the ``kind``
      discriminator) from getting stuck in the supplemental file when the
      SSOT was authored before the field existed.
    """
    index_campaigns = index.setdefault("campaigns", {})
    for key, supplemental in (supplements.get("campaigns") or {}).items():
        existing = index_campaigns.get(key)
        if existing is None:
            index_campaigns[key] = supplemental
            continue
        if not isinstance(supplemental, dict) or not isinstance(existing, dict):
            continue
        for field, val in supplemental.items():
            existing.setdefault(field, val)


def merge_versions(existing: list[str] | None, incoming: list[str]) -> tuple[list[str], bool]:
    old = set(existing or [])
    new = old | set(incoming)
    merged = sorted(new)
    return merged, merged != sorted(old)


def add_unique_list_values(entry: dict[str, Any], field: str, values: list[str]) -> bool:
    old = list(entry.get(field) or [])
    merged = sorted(set(old) | set(values))
    if merged != sorted(set(old)):
        entry[field] = merged
        return True
    return False


def merge_osv_advisory(
    index: dict[str, Any],
    advisory_cfg: dict[str, Any],
    osv: dict[str, Any],
) -> tuple[int, int, int]:
    """Merge one OSV advisory into the SSOT.

    Returns (added, updated, unchanged).
    """
    packages = index.setdefault("packages", [])
    by_key: dict[tuple[str, str], dict[str, Any]] = {
        (p.get("ecosystem", ""), p.get("name", "")): p for p in packages
    }

    advisory_id = advisory_cfg["id"]
    campaign = advisory_cfg.get("campaign", "external_advisory_supplement")
    category = advisory_cfg.get("category", "compromised_legitimate")
    osv_url = f"https://osv.dev/vulnerability/{advisory_id}"
    ghsa_url = None
    for ref in osv.get("references") or []:
        url = ref.get("url") or ""
        if "github.com" in url and "/security/advisories/" in url:
            ghsa_url = url
            break

    added = updated = unchanged = 0
    for row in affected_packages(osv):
        name_only = not row["versions"]
        if name_only and category == "compromised_legitimate":
            # A package-name-only entry for a hijacked legitimate package would
            # block every clean release of that package. Require exact versions
            # for this category; range-only advisories stay out of the SSOT.
            unchanged += 1
            continue

        key = (row["ecosystem"], row["name"])
        existing = by_key.get(key)
        if existing is None:
            entry: dict[str, Any] = {
                "name": row["name"],
                "ecosystem": row["ecosystem"],
                "category": category,
                "campaign": campaign,
                "source": "osv_advisory",
                "confidence": "confirmed",
                "malicious_versions": row["versions"],
                "osv_advisories": [advisory_id],
                "references": [u for u in [osv_url, ghsa_url] if u],
                "notes": advisory_cfg.get("notes", "Imported from OSV advisory."),
            }
            packages.append(entry)
            by_key[key] = entry
            added += 1
            continue

        changed = False
        if row["versions"]:
            merged, version_changed = merge_versions(
                existing.get("malicious_versions"), row["versions"]
            )
            if version_changed:
                existing["malicious_versions"] = merged
                changed = True
        changed |= add_unique_list_values(existing, "osv_advisories", [advisory_id])
        changed |= add_unique_list_values(
            existing, "references", [u for u in [osv_url, ghsa_url] if u]
        )
        if not existing.get("source"):
            existing["source"] = "osv_advisory"
            changed = True
        # A machine-readable advisory promotes the entry to confirmed,
        # regardless of any prior suspected tier.
        if existing.get("confidence") != "confirmed":
            existing["confidence"] = "confirmed"
            changed = True
        if changed:
            updated += 1
        else:
            unchanged += 1

    return added, updated, unchanged


def merge_manual_packages(
    index: dict[str, Any],
    manual_pkgs: list[dict[str, Any]],
) -> tuple[int, int, int]:
    """Merge manually-curated packages (e.g. Socket-only, no OSV ID) into the SSOT.

    Each entry must have at minimum: name, ecosystem, category.
    Returns (added, updated, unchanged).
    """
    packages = index.setdefault("packages", [])
    by_key: dict[tuple[str, str], dict[str, Any]] = {
        (p.get("ecosystem", ""), p.get("name", "")): p for p in packages
    }

    added = updated = unchanged = 0
    for row in manual_pkgs or []:
        name = row.get("name")
        ecosystem = row.get("ecosystem")
        if not name or not ecosystem:
            continue

        key = (ecosystem, name)
        existing = by_key.get(key)

        if existing is None:
            entry: dict[str, Any] = {
                "name": name,
                "ecosystem": ecosystem,
                "category": row.get("category", "malicious_intent"),
                "campaign": row.get("campaign", "external_advisory_supplement"),
                "source": "manual_research",
                "confidence": row.get("confidence", "confirmed"),
                "malicious_versions": row.get("malicious_versions") or [],
                "references": row.get("references") or [],
                "notes": row.get("notes", "Manually curated from external security research."),
            }
            packages.append(entry)
            by_key[key] = entry
            added += 1
            continue

        # If already confirmed via OSV, keep that status and just add references.
        changed = False
        if row.get("malicious_versions"):
            merged, version_changed = merge_versions(
                existing.get("malicious_versions"), row["malicious_versions"]
            )
            if version_changed:
                existing["malicious_versions"] = merged
                changed = True
        changed |= add_unique_list_values(existing, "references", row.get("references") or [])
        if not existing.get("source"):
            existing["source"] = "manual_research"
            changed = True
        if changed:
            updated += 1
        else:
            unchanged += 1

    return added, updated, unchanged


def merge_kisa_listed(
    index: dict[str, Any],
    kisa_cfg: dict[str, Any],
) -> tuple[int, int, int]:
    """Materialize KISA-listed packages into the SSOT as confidence-tagged entries.

    Returns (added, updated, unchanged).
    """
    packages = index.setdefault("packages", [])
    by_key: dict[tuple[str, str], dict[str, Any]] = {
        (p.get("ecosystem", ""), p.get("name", "")): p for p in packages
    }

    campaign = kisa_cfg.get("campaign", "external_advisory_supplement")
    default_category = kisa_cfg.get("default_category", "compromised_legitimate")
    carveouts = {c["package"] for c in kisa_cfg.get("upstream_carveouts") or []}
    refs = list(kisa_cfg.get("references") or [])

    added = updated = unchanged = 0
    for row in kisa_cfg.get("packages") or []:
        name = row.get("name")
        if not name:
            continue
        if name in carveouts:
            unchanged += 1
            continue

        confidence = row.get("confidence", "suspected")
        npm_status = row.get("npm_status", "unknown")
        key = ("npm", name)
        existing = by_key.get(key)

        if existing is None:
            note = (
                "KISA-listed; npm registry returns 404 (consistent with post-incident "
                "takedown). Category between malicious_intent and compromised_legitimate "
                "cannot be determined without npm version history."
                if npm_status == "not_found"
                else "KISA-listed; no OSV/GHSA advisory confirms compromise and upstream "
                "postmortem indicates package remains secure. Retained under "
                "recall-first policy for human review."
            )
            entry = {
                "name": name,
                "ecosystem": "npm",
                "category": default_category,
                "campaign": campaign,
                "source": "kisa_listed",
                "confidence": confidence,
                "npm_status": npm_status,
                "malicious_versions": [],
                "references": refs,
                "notes": note,
            }
            packages.append(entry)
            by_key[key] = entry
            added += 1
            continue

        # If the entry was promoted to confirmed by an OSV advisory, do not
        # demote it. Otherwise stamp KISA metadata onto the existing entry.
        if existing.get("confidence") == "confirmed":
            unchanged += 1
            continue

        changed = False
        if existing.get("confidence") != confidence:
            existing["confidence"] = confidence
            changed = True
        if existing.get("npm_status") != npm_status and npm_status != "unknown":
            existing["npm_status"] = npm_status
            changed = True
        if not existing.get("source"):
            existing["source"] = "kisa_listed"
            changed = True
        changed |= add_unique_list_values(existing, "references", refs)
        if changed:
            updated += 1
        else:
            unchanged += 1

    return added, updated, unchanged


def refresh_from_supplements(
    advisory_filter: set[str] | None = None,
    skip_kisa: bool = False,
    write: bool = False,
) -> int:
    index = load_json(INDEX_PATH)
    supplements = load_json(SUPPLEMENT_PATH)
    ensure_campaigns(index, supplements)

    advisories = supplements.get("osv_advisories") or []
    if advisory_filter:
        advisories = [a for a in advisories if a.get("id") in advisory_filter]

    total_added = total_updated = total_unchanged = 0

    if advisories:
        for advisory_cfg in advisories:
            advisory_id = advisory_cfg.get("id")
            if not advisory_id:
                raise SupplementError("supplemental OSV advisory missing id")
            print(f"Fetching OSV advisory {advisory_id}...")
            osv = fetch_osv_advisory(advisory_id)
            added, updated, unchanged = merge_osv_advisory(index, advisory_cfg, osv)
            print(f"  {advisory_id}: +{added} updated={updated} unchanged={unchanged}")
            total_added += added
            total_updated += updated
            total_unchanged += unchanged
    else:
        print("No supplemental OSV advisories selected.")

    # KISA-listed packages always run after OSV so confirmed advisories can
    # promote KISA-suspected entries to confidence: confirmed.
    if not skip_kisa and not advisory_filter:
        kisa_cfg = supplements.get("kisa_listed_packages")
        if kisa_cfg:
            added, updated, unchanged = merge_kisa_listed(index, kisa_cfg)
            print(
                f"KISA-listed packages: +{added} updated={updated} "
                f"unchanged={unchanged}"
            )
            total_added += added
            total_updated += updated
            total_unchanged += unchanged

    # Manually-curated packages (Socket-only, no OSV ID, etc.)
    if not advisory_filter:
        manual_pkgs = supplements.get("manual_packages") or []
        if manual_pkgs:
            added, updated, unchanged = merge_manual_packages(index, manual_pkgs)
            print(
                f"Manual packages: +{added} updated={updated} unchanged={unchanged}"
            )
            total_added += added
            total_updated += updated
            total_unchanged += unchanged

    if total_added == 0 and total_updated == 0 and total_unchanged == 0:
        return 0

    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    index["generated_at"] = timestamp
    index.setdefault("last_refresh", {})["supplemental_advisories"] = timestamp

    print(
        f"Supplement summary: +{total_added} updated={total_updated} "
        f"unchanged={total_unchanged}"
    )

    if write:
        write_json(INDEX_PATH, index)
        print(f"Wrote {INDEX_PATH}")
    else:
        print("[dry-run] No file written. Re-run with --write to update the SSOT.")

    return 0


def _known_osv_advisory_ids(index: dict[str, Any]) -> set[str]:
    """Return all OSV advisory IDs already recorded in the SSOT."""
    known: set[str] = set()
    for pkg in index.get("packages") or []:
        for aid in pkg.get("osv_advisories") or []:
            known.add(aid)
    return known


def _infer_category(osv: dict[str, Any]) -> str:
    """Infer malicious_intent vs compromised_legitimate from OSV advisory text."""
    text = ((osv.get("summary") or "") + " " + (osv.get("details") or "")).lower()
    if any(kw in text for kw in ("hijacked", "compromised", "account takeover", "stolen credential")):
        return "compromised_legitimate"
    return "malicious_intent"


def _parse_ts(ts: str) -> datetime:
    """Parse an OSV ISO 8601 timestamp into a UTC-aware datetime."""
    ts = re.sub(r"(\.\d{6})\d+", r"\1", ts)   # truncate sub-microsecond digits
    ts = ts.replace("Z", "+00:00")
    return datetime.fromisoformat(ts)


def _is_malicious(osv: dict[str, Any]) -> bool:
    """Return True if this OSV advisory describes active malicious/embedded code.

    Withdrawn advisories are never considered malicious — they represent retracted
    reports or false positives and must be excluded from the SSOT.
    """
    if osv.get("withdrawn"):
        return False
    if (osv.get("id") or "").startswith("MAL-"):
        return True
    for affected in osv.get("affected") or []:
        for cwe in (affected.get("database_specific") or {}).get("cwes") or []:
            if cwe.get("cweId") == "CWE-506":
                return True
    return False


def _fetch_from_full_bundle(
    ecosystem: str,
    known_ids: set[str],
    since_dt: datetime | None = None,
) -> list[tuple[str, dict[str, Any]]]:
    """Download the full all.zip bundle and extract new malicious advisories.

    Used for --full mode (first-time scan of an ecosystem).
    ``since_dt`` is applied as an additional filter when provided.
    """
    url = OSV_GCS_BASE.format(ecosystem=ecosystem)
    print(f"  Downloading OSV {ecosystem} bundle ({url})...")
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "PoisonChain/supplement_malicious_package_index"},
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            bundle = resp.read()
    except urllib.error.URLError as exc:
        print(f"  WARNING: Failed to download OSV {ecosystem} bundle: {exc} — skipping")
        return []

    print(f"  Downloaded {len(bundle) // 1024:,} KB — scanning for new malicious entries...")
    new: list[tuple[str, dict[str, Any]]] = []
    with zipfile.ZipFile(io.BytesIO(bundle)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                osv = json.loads(zf.read(name))
            except (json.JSONDecodeError, KeyError):
                continue
            advisory_id = osv.get("id", "")
            if not advisory_id or advisory_id in known_ids:
                continue
            if not _is_malicious(osv):
                continue
            if since_dt is not None:
                modified_str = osv.get("modified") or osv.get("published") or ""
                if modified_str:
                    try:
                        if _parse_ts(modified_str) < since_dt:
                            continue
                    except ValueError:
                        pass
            new.append((advisory_id, osv))
    return new


def _fetch_from_modified_csv(
    ecosystem: str,
    known_ids: set[str],
    since: str,
) -> list[tuple[str, dict[str, Any]]]:
    """Use modified_id.csv to efficiently fetch only new/changed advisories.

    The CSV is sorted newest-first; we stream it and stop at ``since``.
    Only IDs with a ``MAL-`` prefix are fetched individually (non-malicious
    entries are skipped without an HTTP round-trip).
    Falls back to full bundle download on CSV fetch failure.
    """
    since_dt = _parse_ts(since)
    csv_url = OSV_MODIFIED_CSV_URL.format(ecosystem=ecosystem)
    req = urllib.request.Request(
        csv_url,
        headers={"User-Agent": "PoisonChain/supplement_malicious_package_index"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            csv_text = resp.read().decode("utf-8")
    except urllib.error.URLError as exc:
        print(f"  WARNING: Could not fetch {csv_url}: {exc} — falling back to full bundle")
        return _fetch_from_full_bundle(ecosystem, known_ids, since_dt=since_dt)

    candidate_ids: list[str] = []
    for line in csv_text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(",", 1)
        if len(parts) != 2:
            continue
        ts_str, adv_id = parts[0].strip(), parts[1].strip()
        try:
            ts = _parse_ts(ts_str)
        except ValueError:
            continue
        if ts < since_dt:
            break  # CSV is sorted newest-first — nothing older will be new
        if adv_id not in known_ids and adv_id.startswith("MAL-"):
            candidate_ids.append(adv_id)

    if not candidate_ids:
        return []

    print(f"  {ecosystem}: {len(candidate_ids)} MAL-* candidates via modified_id.csv — fetching...")
    new: list[tuple[str, dict[str, Any]]] = []
    for adv_id in candidate_ids:
        vuln_url = OSV_SINGLE_VULN_URL.format(ecosystem=ecosystem, id=adv_id)
        try:
            req2 = urllib.request.Request(
                vuln_url,
                headers={"User-Agent": "PoisonChain/supplement_malicious_package_index"},
            )
            with urllib.request.urlopen(req2, timeout=30) as resp2:
                osv = json.loads(resp2.read())
        except Exception as exc:
            print(f"  WARNING: Could not fetch {vuln_url}: {exc}")
            continue
        if _is_malicious(osv):
            new.append((adv_id, osv))
    return new


def fetch_new_osv_advisories(
    ecosystem: str,
    known_ids: set[str],
    since: str | None = None,
) -> list[tuple[str, dict[str, Any]]]:
    """Return new malicious advisories for *ecosystem* not in *known_ids*.

    - If ``since`` is None (--full mode): downloads all.zip and scans everything.
    - If ``since`` is set (incremental): uses modified_id.csv to fetch only
      entries modified after ``since``, dramatically reducing bandwidth.

    Returns list of (advisory_id, osv_dict).
    """
    if since is None:
        return _fetch_from_full_bundle(ecosystem, known_ids)
    return _fetch_from_modified_csv(ecosystem, known_ids, since)


def prune_withdrawn_advisories(write: bool = False, lookback_days: int = 14) -> int:
    """Remove SSOT entries whose OSV advisories have been withdrawn.

    Efficiently finds candidates by scanning modified_id.csv: any known advisory
    that OSV has recently modified may have been withdrawn.  Only those candidates
    are queried, keeping HTTP calls to a minimum.  Uses ThreadPoolExecutor for
    parallel fetches so even hundreds of candidates complete quickly.

    On daily runs the lookback window is automatically narrowed to the period
    since the last successful prune (``last_refresh.prune_withdrawn``), so the
    number of candidates stays small.

    Args:
        write:         Persist changes to disk when True; dry-run otherwise.
        lookback_days: Maximum lookback window (days). Overridden by the stored
                       ``last_refresh.prune_withdrawn`` timestamp when available.

    Returns exit-code integer (0 = success).
    """
    import concurrent.futures

    index = load_json(INDEX_PATH)
    packages: list[dict[str, Any]] = index.get("packages") or []
    known_ids = _known_osv_advisory_ids(index)

    # Use stored prune timestamp when available (narrower window = fewer checks)
    stored_prune_ts: str | None = (index.get("last_refresh") or {}).get("prune_withdrawn")
    if stored_prune_ts:
        since_dt = _parse_ts(stored_prune_ts)
    else:
        since_dt = datetime.now(timezone.utc) - timedelta(days=lookback_days)

    print(
        f"Checking for withdrawn OSV advisories "
        f"(modified since {since_dt.date()}, across {len(OSV_BULK_ECOSYSTEMS)} ecosystems)..."
    )

    # Collect advisory IDs to recheck (appear in modified CSV + already in SSOT)
    recheck_ids: set[str] = set()
    for ecosystem in OSV_BULK_ECOSYSTEMS:
        csv_url = OSV_MODIFIED_CSV_URL.format(ecosystem=ecosystem)
        req = urllib.request.Request(
            csv_url,
            headers={"User-Agent": "PoisonChain/supplement_malicious_package_index"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                csv_text = resp.read().decode("utf-8")
        except urllib.error.URLError as exc:
            print(f"  WARNING: Could not fetch {csv_url}: {exc}")
            continue

        eco_candidates: list[str] = []
        for line in csv_text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(",", 1)
            if len(parts) != 2:
                continue
            ts_str, adv_id = parts[0].strip(), parts[1].strip()
            try:
                ts = _parse_ts(ts_str)
            except ValueError:
                continue
            if ts < since_dt:
                break  # CSV is sorted newest-first
            if adv_id in known_ids and adv_id.startswith("MAL-"):
                eco_candidates.append(adv_id)
        if eco_candidates:
            print(f"  {ecosystem}: {len(eco_candidates)} known advisory ID(s) to recheck")
            recheck_ids.update(eco_candidates)

    if not recheck_ids:
        print("No recently-modified known advisories found — SSOT is clean.")
        _bump_prune_timestamp(index, write)
        return 0

    print(f"Fetching {len(recheck_ids)} advisory ID(s) in parallel (8 workers)...")

    def _check_one(adv_id: str) -> tuple[str, bool]:
        """Return (adv_id, is_withdrawn)."""
        url = f"https://api.osv.dev/v1/vulns/{adv_id}"
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "PoisonChain/supplement_malicious_package_index"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                osv = json.loads(resp.read())
            return adv_id, bool(osv.get("withdrawn"))
        except Exception:
            return adv_id, False  # Treat fetch errors as "not withdrawn"

    withdrawn_ids: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        for adv_id, is_withdrawn in executor.map(_check_one, sorted(recheck_ids)):
            if is_withdrawn:
                withdrawn_ids.add(adv_id)
                print(f"  WITHDRAWN: {adv_id}")

    if not withdrawn_ids:
        print("No withdrawn advisories found — SSOT is clean.")
        _bump_prune_timestamp(index, write)
        return 0

    print(f"\nPruning {len(withdrawn_ids)} withdrawn advisory ID(s) from SSOT...")
    kept: list[dict[str, Any]] = []
    removed_count = 0
    for pkg in packages:
        pkg_advs = set(pkg.get("osv_advisories") or [])
        withdrawn_here = pkg_advs & withdrawn_ids
        if not withdrawn_here:
            kept.append(pkg)
            continue

        active_advs = pkg_advs - withdrawn_ids
        if not active_advs and pkg.get("source") == "osv_advisory":
            # All advisories withdrawn and entry came solely from OSV → delete
            print(f"  REMOVE  {pkg['ecosystem']}/{pkg['name']}: {', '.join(sorted(withdrawn_here))}")
            removed_count += 1
        else:
            # Keep package but strip withdrawn advisory refs
            pkg["osv_advisories"] = [
                a for a in (pkg.get("osv_advisories") or []) if a not in withdrawn_ids
            ]
            pkg["references"] = [
                r for r in (pkg.get("references") or [])
                if not any(wid in r for wid in withdrawn_ids)
            ]
            print(f"  PRUNE   {pkg['ecosystem']}/{pkg['name']}: removed refs {withdrawn_here}")
            kept.append(pkg)

    print(f"\nPrune summary: {removed_count} package(s) removed from SSOT")

    eco_counts: dict[str, int] = {}
    for pkg in kept:
        e = pkg.get("ecosystem", "unknown")
        eco_counts[e] = eco_counts.get(e, 0) + 1

    index["packages"] = kept
    index["total_count"] = len(kept)
    index["ecosystem_counts"] = eco_counts
    index["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _bump_prune_timestamp(index, write)

    if write:
        write_json(INDEX_PATH, index)
        print(f"Wrote {INDEX_PATH}")
    else:
        print("[dry-run] Re-run with --prune-withdrawn --write to apply changes.")

    return 0


def _bump_prune_timestamp(index: dict[str, Any], write: bool) -> None:
    """Update last_refresh.prune_withdrawn to now (written only when write=True)."""
    index.setdefault("last_refresh", {})["prune_withdrawn"] = (
        datetime.now(timezone.utc).isoformat(timespec="seconds")
    )


def refresh_from_osv_malicious(
    write: bool = False, full: bool = False, ecosystems: list[str] | None = None
) -> int:
    """Auto-discover and merge new malicious advisories across all supported ecosystems.

    Scans OSV GCS bulk bundles for npm, PyPI, Maven, crates.io, Go and NuGet.
    This bridges the gap where Datadog hasn't picked up a new OSV entry yet
    and the advisory isn't listed in supplemental-malicious-package-sources.json.

    If ``full`` is True, ignore the last_refresh timestamp and scan all OSV history.
    Useful when adding a new ecosystem for the first time.

    If ``ecosystems`` is given, only those ecosystems are scanned (e.g. ['Maven','Go','NuGet']).
    """
    # Case-insensitive match so users can pass 'pypi', 'nuget', etc.
    eco_lower = {e.lower(): e for e in OSV_BULK_ECOSYSTEMS}
    target_ecosystems = (
        [eco_lower[e.lower()] for e in ecosystems if e.lower() in eco_lower]
        if ecosystems else list(OSV_BULK_ECOSYSTEMS)
    )
    index = load_json(INDEX_PATH)
    known_ids = _known_osv_advisory_ids(index)
    # Per-ecosystem last_refresh timestamps live under last_refresh.osv_malicious_by_eco.
    # A single legacy key (osv_malicious) is also supported for backward compat.
    eco_refresh_map: dict[str, str] = (
        (index.get("last_refresh") or {}).get("osv_malicious_by_eco") or {}
    )
    legacy_ts: str | None = (index.get("last_refresh") or {}).get("osv_malicious")

    print(f"Known OSV advisory IDs in SSOT: {len(known_ids)}")
    if full:
        print("--full mode: ignoring last_refresh timestamps — scanning entire OSV history")
    print(f"Scanning OSV GCS bundles for ecosystems: {', '.join(target_ecosystems)}")

    all_new: list[tuple[str, dict[str, Any]]] = []
    for ecosystem in target_ecosystems:
        if full:
            since: str | None = None  # full bundle scan
        else:
            # Per-ecosystem timestamp takes priority; fall back to legacy single key.
            since = eco_refresh_map.get(ecosystem) or legacy_ts
            if since is None:
                # First run for this ecosystem: limit to last 48 h via CSV
                since = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat(timespec="seconds")
                print(f"  {ecosystem}: no prior refresh — scanning last 48 h")
            else:
                print(f"  {ecosystem}: last refresh {since[:10]} — scanning for changes since then")
        eco_new = fetch_new_osv_advisories(ecosystem, known_ids, since=since)
        print(f"  {ecosystem}: {len(eco_new)} new advisories")
        all_new.extend(eco_new)
        # Keep known_ids up-to-date so duplicates across bundles are de-duped.
        known_ids.update(adv_id for adv_id, _ in eco_new)

    noun = "advisory" if len(all_new) == 1 else "advisories"
    print(f"Found {len(all_new)} new {noun} not yet in SSOT.")

    if not all_new:
        print("SSOT is already up to date with ossf/malicious-packages.")
        return 0

    index["campaigns"].setdefault("osv_auto", {
        "name": "OSSF malicious-packages (OSV auto-imported)",
        "kind": "catalog",
        "source": "https://github.com/ossf/malicious-packages",
        "notes": (
            "Auto-imported daily by .github/workflows/refresh-malicious-packages.yml "
            "from ossf/malicious-packages. "
            "Entries with campaign='osv_auto' are auto-refreshed; do not edit by hand."
        ),
    })

    total_added = total_updated = total_unchanged = 0
    for advisory_id, osv in all_new:
        advisory_cfg: dict[str, Any] = {
            "id": advisory_id,
            "campaign": "osv_auto",
            "category": _infer_category(osv),
        }
        added, updated, unchanged = merge_osv_advisory(index, advisory_cfg, osv)
        if added or updated:
            print(f"  {advisory_id}: +{added} added, {updated} updated")
        total_added += added
        total_updated += updated
        total_unchanged += unchanged

    if total_added == 0 and total_updated == 0:
        print("No SSOT changes after merging new advisories.")
        return 0

    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    index["generated_at"] = timestamp
    lr = index.setdefault("last_refresh", {})
    lr["osv_malicious"] = timestamp  # legacy key for backward compat
    # Per-ecosystem timestamps: update all ecosystems scanned in this run
    lr.setdefault("osv_malicious_by_eco", {}).update(
        {eco: timestamp for eco in target_ecosystems}
    )

    print(
        f"OSV auto-discovery summary: +{total_added} added, "
        f"{total_updated} updated, {total_unchanged} unchanged"
    )

    if write:
        write_json(INDEX_PATH, index)
        print(f"Wrote {INDEX_PATH}")
    else:
        print("[dry-run] Re-run with --refresh-osv --write to apply changes.")

    # After adding new advisories, prune any that OSV has since withdrawn.
    print("\nRunning withdrawn-advisory prune pass...")
    prune_withdrawn_advisories(write=write)

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--advisory",
        action="append",
        help="Only import this OSV advisory ID. Can be supplied more than once.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write public/data/malicious-packages.json. Default is dry-run.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Explicitly run without writing. This is the default.",
    )
    parser.add_argument(
        "--skip-kisa",
        action="store_true",
        help="Skip kisa_listed_packages materialization (advisory-only run).",
    )
    parser.add_argument(
        "--refresh-osv",
        action="store_true",
        help=(
            "Auto-discover new malicious advisories from OSV GCS bundles "
            "(npm, PyPI, Maven, crates.io, Go, NuGet) and merge into the SSOT."
        ),
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help=(
            "With --refresh-osv: ignore the last_refresh timestamp and scan entire "
            "OSV history. Use when adding a new ecosystem for the first time."
        ),
    )
    parser.add_argument(
        "--ecosystems",
        nargs="+",
        metavar="ECO",
        help=(
            "With --refresh-osv: limit scan to these ecosystems only "
            "(e.g. --ecosystems Maven Go NuGet). Useful for first-time backfill "
            "of a single ecosystem without re-scanning all others."
        ),
    )
    parser.add_argument(
        "--prune-withdrawn",
        action="store_true",
        help=(
            "Scan OSV modified_id.csv for recently-withdrawn advisories and remove "
            "them from the SSOT.  Safe to run standalone or after --refresh-osv. "
            "Requires --write to persist changes."
        ),
    )
    args = parser.parse_args()

    if args.write and args.dry_run:
        print("ERROR: choose either --write or --dry-run, not both", file=sys.stderr)
        return 2

    try:
        if args.refresh_osv:
            return refresh_from_osv_malicious(
                write=args.write,
                full=args.full,
                ecosystems=args.ecosystems,
            )
        if args.prune_withdrawn:
            return prune_withdrawn_advisories(write=args.write)
        return refresh_from_supplements(
            advisory_filter=set(args.advisory or []) or None,
            skip_kisa=args.skip_kisa,
            write=args.write,
        )
    except SupplementError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
