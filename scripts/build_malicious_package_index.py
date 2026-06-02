#!/usr/bin/env python3
"""
Build / validate the curated malicious-package index.

This script is the gatekeeper for ``public/data/malicious-packages.json`` —
the single source of truth that downstream scripts (canisterworm_analysis,
canisterworm_lockfile_scan, preserve_evidence, nexus_proxy_scan) all read.

Usage:
    python3 scripts/build_malicious_package_index.py --validate
    python3 scripts/build_malicious_package_index.py --check-datadog
    python3 scripts/build_malicious_package_index.py --diff-legacy

The JSON is hand-curated, not auto-generated. This tool only validates the
file and (optionally) cross-checks individual entries against the Datadog
malicious-software-packages-dataset to catch category drift.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

ROOT_DIR = Path(__file__).resolve().parent.parent
INDEX_PATH = ROOT_DIR / "public" / "data" / "malicious-packages.json"

DATADOG_REPO = "DataDog/malicious-software-packages-dataset"

VALID_CATEGORIES = {"compromised_legitimate", "malicious_intent", "unknown"}
VALID_CONFIDENCE = {"confirmed", "suspected"}
VALID_NPM_STATUS = {"exists", "not_found", "unknown"}
VALID_CAMPAIGN_KIND = {"incident", "catalog"}


def load_env(path: Path = ROOT_DIR / ".env") -> None:
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


load_env()
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")


def _github_headers() -> dict:
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "PoisonChain/build_malicious_package_index",
    }
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


def load_index() -> dict:
    if not INDEX_PATH.exists():
        sys.exit(f"ERROR: index not found at {INDEX_PATH}")
    try:
        return json.loads(INDEX_PATH.read_text())
    except json.JSONDecodeError as e:
        sys.exit(f"ERROR: invalid JSON in {INDEX_PATH}: {e}")


def validate_index(data: dict) -> list[str]:
    errors: list[str] = []

    if data.get("schema_version") != "1.0":
        errors.append(f"unexpected schema_version: {data.get('schema_version')!r}")

    campaigns = data.get("campaigns") or {}
    if not isinstance(campaigns, dict) or not campaigns:
        errors.append("campaigns missing or empty")
    for cid, cdef in (campaigns or {}).items():
        if not isinstance(cdef, dict):
            errors.append(f"campaigns.{cid}: must be an object")
            continue
        kind = cdef.get("kind")
        if kind is None:
            errors.append(
                f"campaigns.{cid}: missing 'kind' "
                f"(expected one of {sorted(VALID_CAMPAIGN_KIND)})"
            )
        elif kind not in VALID_CAMPAIGN_KIND:
            errors.append(
                f"campaigns.{cid}: invalid kind {kind!r} "
                f"(expected one of {sorted(VALID_CAMPAIGN_KIND)})"
            )
        elif kind == "incident" and not cdef.get("attack_window"):
            # Soft requirement: incidents normally carry a window. We only
            # warn so a new incident can be tracked while its timeline is
            # still being reconstructed.
            print(
                f"WARNING: campaigns.{cid} has kind='incident' but no "
                "attack_window — add one when the timeline is confirmed."
            )

    packages = data.get("packages") or []
    if not isinstance(packages, list) or not packages:
        errors.append("packages missing or empty")

    seen: set[tuple[str, str]] = set()
    for i, p in enumerate(packages):
        prefix = f"packages[{i}] ({p.get('name', '?')})"
        for required in ("name", "ecosystem", "category", "campaign"):
            if required not in p:
                errors.append(f"{prefix}: missing required field '{required}'")
        if p.get("category") not in VALID_CATEGORIES:
            errors.append(f"{prefix}: invalid category {p.get('category')!r}")
        if p.get("campaign") not in campaigns:
            errors.append(f"{prefix}: unknown campaign {p.get('campaign')!r}")
        if not isinstance(p.get("malicious_versions", []), list):
            errors.append(f"{prefix}: malicious_versions must be a list")
        if "confidence" in p and p["confidence"] not in VALID_CONFIDENCE:
            errors.append(f"{prefix}: invalid confidence {p.get('confidence')!r}")
        if "npm_status" in p and p["npm_status"] not in VALID_NPM_STATUS:
            errors.append(f"{prefix}: invalid npm_status {p.get('npm_status')!r}")
        key = (p.get("ecosystem", ""), p.get("name", ""))
        if key in seen:
            errors.append(f"{prefix}: duplicate (ecosystem, name) entry")
        seen.add(key)

    return errors


def check_datadog_categories(data: dict, only: Iterable[str] | None = None) -> list[str]:
    """For each package, GET the two Datadog paths and warn on mismatches.

    Returns a list of warning strings (empty = all OK).
    """
    # Maps SSOT ecosystem → Datadog directory name
    eco_to_dd: dict[str, str] = {
        "npm": "npm",
        "PyPI": "pypi",
    }

    warnings: list[str] = []
    only_set = set(only or [])
    for p in data["packages"]:
        if only_set and p["name"] not in only_set:
            continue
        eco = p.get("ecosystem", "")
        dd_dir = eco_to_dd.get(eco)
        if dd_dir is None:
            continue  # ecosystem not tracked in Datadog dataset
        name = p["name"]
        # encode @-scoped (npm) and path-unsafe chars for the URL
        encoded = name.replace("/", "%2F")
        in_compromised_lib = _datadog_has(
            f"contents/samples/{dd_dir}/compromised_lib/{encoded}"
        )
        in_malicious_intent = _datadog_has(
            f"contents/samples/{dd_dir}/malicious_intent/{encoded}"
        )

        observed: str | None = None
        if in_compromised_lib and not in_malicious_intent:
            observed = "compromised_legitimate"
        elif in_malicious_intent and not in_compromised_lib:
            observed = "malicious_intent"
        elif in_compromised_lib and in_malicious_intent:
            warnings.append(
                f"{name} ({eco}): present in BOTH Datadog paths — manual review needed"
            )
            continue
        else:
            # Not in Datadog at all — not necessarily wrong (Datadog hasn't archived it).
            continue

        if observed != p["category"]:
            warnings.append(
                f"{name} ({eco}): index says category={p['category']!r} but Datadog "
                f"path implies {observed!r}"
            )

    return warnings


def _gh_tree(sha_or_branch: str, recursive: bool = False) -> dict:
    suffix = "?recursive=1" if recursive else ""
    url = (f"https://api.github.com/repos/{DATADOG_REPO}/git/trees/"
           f"{sha_or_branch}{suffix}")
    req = urllib.request.Request(url, headers=_github_headers())
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def fetch_datadog_tree() -> dict[tuple[str, str, str], dict[str, str]]:
    """Return {(ecosystem, category, pkg_name) → {version: date_str}} from the Datadog dataset.

    Only fetches *tree metadata* (~MBs) from GitHub — never downloads the
    actual ZIP blobs (~20GB). Splits per-category to avoid the truncation
    that hits a single recursive call against the whole repo.

    ecosystem ∈ {'npm', 'PyPI'}.
    category ∈ {'compromised_legitimate', 'malicious_intent'}.
    pkg_name returned in canonical form (@scope/name for npm, bare name for PyPI).
    """
    t = _gh_tree("main")
    samples_sha = next(e["sha"] for e in t["tree"] if e["path"] == "samples")
    t = _gh_tree(samples_sha)
    ecosystem_shas = {e["path"]: e["sha"] for e in t["tree"] if e["type"] == "tree"}

    # Maps Datadog directory name → SSOT ecosystem name
    dd_ecosystems: dict[str, str] = {
        "npm": "npm",
        "pypi": "PyPI",
    }

    dd_to_canonical = {
        "compromised_lib": "compromised_legitimate",
        "malicious_intent": "malicious_intent",
    }

    # Datadog path structure: <pkg>/<version>/<YYYY-MM-DD-name-vX.Y.Z.zip>
    # npm scoped packages are stored as @scope@pkg, normalized below to @scope/pkg.
    path_re = re.compile(r"^([^/]+)/([^/]+)/([^/]+)$")
    date_re = re.compile(r"(\d{4}-\d{2}-\d{2})")

    out: dict[tuple[str, str, str], dict[str, str]] = defaultdict(dict)
    for dd_eco, ssot_eco in dd_ecosystems.items():
        eco_sha = ecosystem_shas.get(dd_eco)
        if not eco_sha:
            print(f"WARN: Datadog {dd_eco} directory not found — skipping",
                  file=sys.stderr)
            continue
        eco_tree = _gh_tree(eco_sha)
        cat_shas = {e["path"]: e["sha"] for e in eco_tree["tree"] if e["type"] == "tree"}

        for dd_cat, our_cat in dd_to_canonical.items():
            if dd_cat not in cat_shas:
                continue
            sub = _gh_tree(cat_shas[dd_cat], recursive=True)
            if sub.get("truncated"):
                print(f"WARN: Datadog {dd_eco}/{dd_cat} tree truncated — some entries missed",
                      file=sys.stderr)
            for entry in sub.get("tree", []):
                if entry.get("type") != "blob":
                    continue
                m = path_re.match(entry["path"])
                if not m:
                    continue
                pkg_raw, version, filename = m.groups()
                # npm scoped package normalisation: @scope@pkg → @scope/pkg
                if ssot_eco == "npm" and pkg_raw.startswith("@") and "@" in pkg_raw[1:]:
                    parts = pkg_raw.split("@")
                    if len(parts) >= 3:
                        pkg_name = f"@{parts[1]}/{parts[2]}"
                    else:
                        pkg_name = pkg_raw
                else:
                    pkg_name = pkg_raw
                d = date_re.search(filename)
                date_str = d.group(1) if d else ""
                out[(ssot_eco, our_cat, pkg_name)][version] = date_str
    return out


def refresh_from_datadog(dry_run: bool = False) -> tuple[int, int, int]:
    """Merge the Datadog dataset into the SSOT.

    Rules:
      - Manual campaigns are preserved verbatim (their entries are not touched).
      - All packages: store malicious_versions, datadog_added (earliest
        discovery date from the ZIP filename), and version_dates
        ({version: "YYYY-MM-DD"}) for date-based queries.
      - Existing datadog_auto entries get their malicious_versions refreshed
        from the latest Datadog tree (Datadog is authoritative for them).
      - Never delete entries — once known malicious, always tracked.

    Returns (added, updated, unchanged).
    """
    data = load_index()
    # Key by (ecosystem, name) to support multi-ecosystem dedup
    by_key: dict[tuple[str, str], dict] = {
        (p["ecosystem"], p["name"]): p for p in data["packages"]
    }

    print(f"Existing SSOT: {len(data['packages'])} packages")
    print("Fetching Datadog tree (metadata only, no ZIP downloads)...")
    found = fetch_datadog_tree()
    print(f"Datadog: {len(found)} (ecosystem, category, package) entries")

    data.setdefault("campaigns", {})
    if "datadog_auto" not in data["campaigns"]:
        data["campaigns"]["datadog_auto"] = {
            "name": "Datadog malicious-software-packages-dataset (auto-imported)",
            "source": "https://github.com/DataDog/malicious-software-packages-dataset",
            "notes": "Synced daily by .github/workflows/refresh-malicious-packages.yml. "
                     "This campaign's entries are authoritative-refreshed; do not edit by hand.",
        }

    added = 0
    updated = 0
    unchanged = 0

    for (ecosystem, category, pkg_name), versions in sorted(found.items()):
        existing = by_key.get((ecosystem, pkg_name))

        if existing is None:
            new_entry: dict = {
                "name": pkg_name,
                "ecosystem": ecosystem,
                "category": category,
                "campaign": "datadog_auto",
                "source": "datadog_dataset",
                "malicious_versions": sorted(versions.keys()),
                "version_dates": dict(sorted(versions.items())),
            }
            dates = [d for d in versions.values() if d]
            if dates:
                new_entry["datadog_added"] = min(dates)
            data["packages"].append(new_entry)
            by_key[(ecosystem, pkg_name)] = new_entry
            added += 1
            continue

        # Existing entry — only auto-refresh datadog_auto entries.
        if existing.get("campaign") != "datadog_auto":
            unchanged += 1
            continue

        old_vers = set(existing.get("malicious_versions") or [])
        new_vers = set(versions.keys())
        old_vdates = existing.get("version_dates") or {}
        merged_dates = {**old_vdates, **versions}

        changed = False
        if old_vers != new_vers:
            existing["malicious_versions"] = sorted(new_vers)
            changed = True
        if merged_dates != old_vdates:
            existing["version_dates"] = dict(sorted(merged_dates.items()))
            changed = True

        all_dates = [d for d in merged_dates.values() if d]
        if all_dates:
            new_added = min(all_dates)
            if existing.get("datadog_added") != new_added:
                existing["datadog_added"] = new_added
                changed = True

        if changed:
            updated += 1
        else:
            unchanged += 1

    data["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    data.setdefault("last_refresh", {})["datadog"] = data["generated_at"]
    data["_comment"] = (
        "Single source of truth for malicious packages (npm, PyPI, and more) tracked by PoisonChain. "
        "campaigns.<id>.kind: 'incident' = single coordinated attack with bounded attack_window and (usually) "
        "an attributed actor — valid target for campaign-specific analyzers like scripts/canisterworm_analysis.py. "
        "'catalog' = continuous-import bucket (e.g. datadog_auto) or meta placeholder — NOT a real campaign. "
        "Generic SSOT-driven scanners consume both kinds the same way; IOC matchers should skip catalogs because "
        "there is no shared attack_window or actor. "
        "category: 'compromised_legitimate' = legitimate package whose specific versions were hijacked; "
        "'malicious_intent' = package was malicious from the start (typosquat etc.). "
        "confidence (optional): 'confirmed' = machine-readable advisory (OSV/GHSA/Datadog) or authoritative "
        "listing combined with npm registry takedown; 'suspected' = secondary source (e.g. KISA) lists the "
        "package but upstream postmortem / OSV does not confirm — scanners surface these in a lower-severity section. "
        "npm_status (optional): 'exists' | 'not_found' | 'unknown' — registry presence; 'not_found' may indicate "
        "post-incident unpublish. "
        "datadog_added: earliest date the package appeared in the Datadog dataset (ZIP filename prefix). "
        "version_dates: {version: 'YYYY-MM-DD'} maps each version to its Datadog discovery date. "
        "For Nexus/lockfile scans, malicious_intent packages are inherently dangerous by name, "
        "while compromised_legitimate packages are only dangerous at specific listed versions."
    )

    print(f"Added: {added}, Updated: {updated}, Unchanged: {unchanged}")

    if dry_run:
        print("[dry-run] No file written.")
        return added, updated, unchanged

    INDEX_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    print(f"✅ Wrote {INDEX_PATH}")
    return added, updated, unchanged


def _datadog_has(path: str) -> bool:
    url = f"https://api.github.com/repos/{DATADOG_REPO}/{path}"
    req = urllib.request.Request(url, headers=_github_headers())
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status == 200
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        # 403 (rate-limited) → treat as "unknown" and skip rather than fail
        return False
    except Exception:
        return False


def diff_legacy(data: dict) -> list[str]:
    """Cross-check that legacy constants match the SSOT.

    This catches drift in the rare event someone edits one of the constants
    directly instead of the JSON.
    """
    diffs: list[str] = []

    # Lazy import so this script still works if the others move
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        from canisterworm_analysis import CANISTERWORM_PACKAGES  # type: ignore
    except Exception as e:
        diffs.append(f"could not import canisterworm_analysis: {e}")
        CANISTERWORM_PACKAGES = set()
    try:
        from canisterworm_lockfile_scan import MALICIOUS_PACKAGES  # type: ignore
    except Exception as e:
        diffs.append(f"could not import canisterworm_lockfile_scan: {e}")
        MALICIOUS_PACKAGES = {}

    index_canister_names = {
        p["name"] for p in data["packages"] if p["campaign"] == "canisterworm"
    }
    index_malicious_versions = {
        p["name"]: list(p.get("malicious_versions") or [])
        for p in data["packages"]
        if p["campaign"] == "canisterworm" and p.get("malicious_versions")
    }

    only_in_legacy = CANISTERWORM_PACKAGES - index_canister_names
    only_in_index = index_canister_names - CANISTERWORM_PACKAGES
    if only_in_legacy:
        diffs.append(
            f"CANISTERWORM_PACKAGES has {len(only_in_legacy)} names not in index: "
            f"{sorted(only_in_legacy)}"
        )
    if only_in_index:
        diffs.append(
            f"index has {len(only_in_index)} canisterworm names not in legacy: "
            f"{sorted(only_in_index)}"
        )

    for name, vers in MALICIOUS_PACKAGES.items():
        idx_vers = index_malicious_versions.get(name)
        if idx_vers is None:
            diffs.append(f"MALICIOUS_PACKAGES has {name} but index doesn't")
        elif sorted(idx_vers) != sorted(vers):
            diffs.append(
                f"{name}: legacy versions {sorted(vers)} vs index {sorted(idx_vers)}"
            )

    return diffs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate the JSON schema and exit. (default action if no flags given)",
    )
    parser.add_argument(
        "--check-datadog",
        action="store_true",
        help="Cross-check each entry's category against the Datadog dataset path "
             "(slow, hits GitHub API — set GITHUB_TOKEN to avoid rate limits).",
    )
    parser.add_argument(
        "--diff-legacy",
        action="store_true",
        help="Diff the JSON against the legacy hardcoded constants in the other scripts.",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Pull latest Datadog malicious-package metadata (tree only, no "
             "blob downloads) and merge into the SSOT. Manual campaigns are "
             "preserved; auto entries are refreshed.",
    )
    parser.add_argument(
        "--only",
        nargs="+",
        help="Limit --check-datadog to these package names.",
    )
    parser.add_argument(
        "--diff-summary",
        action="store_true",
        help="Compare the current SSOT against HEAD's version and print a "
             "one-line summary like '+12 -0 (total 13040)'. Used by the "
             "daily refresh workflow for commit messages.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="With --diff-summary, only print the summary line (no headers).",
    )
    args = parser.parse_args()

    # default: validate
    if not (args.validate or args.check_datadog or args.diff_legacy or args.refresh
            or args.diff_summary):
        args.validate = True

    if args.diff_summary:
        # Compare current working file against HEAD's version.
        import subprocess
        try:
            head_blob = subprocess.run(
                ["git", "show", "HEAD:public/data/malicious-packages.json"],
                capture_output=True, text=True, check=False,
            ).stdout
            old = json.loads(head_blob) if head_blob.strip() else {"packages": []}
        except Exception:
            old = {"packages": []}
        new = load_index()
        old_names = {p["name"] for p in old.get("packages", [])}
        new_names = {p["name"] for p in new.get("packages", [])}
        added_n = len(new_names - old_names)
        removed_n = len(old_names - new_names)
        total = len(new_names)
        if args.quiet:
            print(f"+{added_n} -{removed_n} (total {total})")
        else:
            print(f"SSOT diff vs HEAD: +{added_n} added, -{removed_n} removed, total {total}")
        return 0

    data = load_index()

    rc = 0

    if args.validate:
        errors = validate_index(data)
        if errors:
            print(f"❌ {len(errors)} validation errors:")
            for e in errors:
                print(f"   - {e}")
            rc = 1
        else:
            print(
                f"✅ Schema valid: {len(data['packages'])} packages, "
                f"{len(data['campaigns'])} campaigns"
            )
            from collections import Counter
            by_cat = Counter(p["category"] for p in data["packages"])
            by_camp = Counter(p["campaign"] for p in data["packages"])
            print(f"   categories: {dict(by_cat)}")
            print(f"   campaigns:  {dict(by_camp)}")

    if args.diff_legacy:
        diffs = diff_legacy(data)
        if diffs:
            print(f"\n⚠️  {len(diffs)} legacy / index mismatches:")
            for d in diffs:
                print(f"   - {d}")
            rc = 1
        else:
            print("\n✅ Legacy constants and index agree")

    if args.check_datadog:
        if not GITHUB_TOKEN:
            print(
                "\nℹ️  GITHUB_TOKEN not set — GitHub API rate limit is 60 req/hr; "
                "check may be incomplete"
            )
        warnings = check_datadog_categories(data, only=args.only)
        if warnings:
            print(f"\n⚠️  {len(warnings)} category drift warnings vs Datadog:")
            for w in warnings:
                print(f"   - {w}")
        else:
            print("\n✅ All checked entries agree with Datadog paths")

    if args.refresh:
        if not GITHUB_TOKEN:
            print("\nℹ️  GITHUB_TOKEN not set — GitHub API rate limit is 60 req/hr")
        try:
            refresh_from_datadog(dry_run=False)
        except Exception as e:
            print(f"\n❌ Refresh failed: {e}", file=sys.stderr)
            rc = 1

    return rc


if __name__ == "__main__":
    sys.exit(main())
