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
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
INDEX_PATH = ROOT_DIR / "public" / "data" / "malicious-packages.json"
SUPPLEMENT_PATH = ROOT_DIR / "public" / "data" / "supplemental-malicious-package-sources.json"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"


class SupplementError(RuntimeError):
    pass


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
    if not value:
        return ""
    if value.lower() == "npm":
        return "npm"
    return value


def affected_npm_packages(osv: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract canonical npm package/version rows from one OSV advisory."""
    rows: list[dict[str, Any]] = []
    for affected in osv.get("affected", []) or []:
        package = affected.get("package") or {}
        ecosystem = normalize_ecosystem(package.get("ecosystem"))
        name = package.get("name")
        if ecosystem != "npm" or not name:
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
    index_campaigns = index.setdefault("campaigns", {})
    for key, value in (supplements.get("campaigns") or {}).items():
        index_campaigns.setdefault(key, value)


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
    for row in affected_npm_packages(osv):
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
    args = parser.parse_args()

    if args.write and args.dry_run:
        print("ERROR: choose either --write or --dry-run, not both", file=sys.stderr)
        return 2

    try:
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
