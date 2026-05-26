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
        if not row["versions"]:
            # For compromised legitimate packages, a package-name-only entry would
            # create too much false-positive risk. Keep range-only advisories out
            # of the SSOT unless exact versions are available.
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
        if changed:
            updated += 1
        else:
            unchanged += 1

    return added, updated, unchanged


def refresh_from_supplements(
    advisory_filter: set[str] | None = None,
    write: bool = False,
) -> int:
    index = load_json(INDEX_PATH)
    supplements = load_json(SUPPLEMENT_PATH)
    ensure_campaigns(index, supplements)

    advisories = supplements.get("osv_advisories") or []
    if advisory_filter:
        advisories = [a for a in advisories if a.get("id") in advisory_filter]

    if not advisories:
        print("No supplemental OSV advisories selected.")
        return 0

    total_added = total_updated = total_unchanged = 0
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
    args = parser.parse_args()

    if args.write and args.dry_run:
        print("ERROR: choose either --write or --dry-run, not both", file=sys.stderr)
        return 2

    try:
        return refresh_from_supplements(
            advisory_filter=set(args.advisory or []) or None,
            write=args.write,
        )
    except SupplementError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
