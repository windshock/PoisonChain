#!/usr/bin/env python3
"""
Forensic evidence preservation for CanisterWorm npm supply chain attack.
Downloads and stores malicious npm packages (axios@1.14.1, axios@0.30.4,
plain-crypto-js@4.2.1) from multiple sources before they disappear.

Usage:
    python3 scripts/preserve_evidence.py [--dry-run] [--force]
"""

import argparse
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def load_env(path=".env"):
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())


load_env()

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

MALICIOUS_PACKAGES = [
    {"name": "axios", "version": "1.14.1"},
    {"name": "axios", "version": "0.30.4"},
    {"name": "plain-crypto-js", "version": "4.2.1"},
]

# SANS-published reference hashes for verification
KNOWN_HASHES = {
    "axios@0.30.4": {
        "sha1": "d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71",
        "note": "SANS-published reference hash for tarball",
    },
    "plain-crypto-js@4.2.1": {
        "sha1": "07d889e2dadce6f3910dcbc253317d28ca61c766",
        "note": "SANS-published reference hash for tarball",
    },
    "setup.js": {
        "sha256": "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09",
        "note": "SILKBELL dropper SHA256",
    },
}

DATADOG_REPO = "DataDog/malicious-software-packages-dataset"
ROOT_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = ROOT_DIR / "public" / "evidence"
REPORTS_DIR = ROOT_DIR / "internal" / "reports" / "data"


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _github_headers():
    h = {"Accept": "application/vnd.github+json", "User-Agent": "PoisonChain/preserve_evidence"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


def _fetch_bytes(url: str, headers: dict | None = None, timeout: int = 30) -> bytes | None:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "PoisonChain/preserve_evidence"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code in (403, 404, 410):
            return None
        raise
    except Exception:
        return None


def _fetch_json(url: str, headers: dict | None = None) -> dict | list | None:
    data = _fetch_bytes(url, headers=headers)
    if data is None:
        return None
    try:
        return json.loads(data)
    except Exception:
        return None


# ── Hash helpers ──────────────────────────────────────────────────────────────

def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha1_of(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


# ── Acquisition strategies ────────────────────────────────────────────────────

def try_datadog_github(name: str, version: str, dry_run: bool, save_dir: Path | None = None) -> bytes | None:
    """
    Fetch from Datadog's malicious-packages-dataset repo.

    Datadog ZIP structure: extracted package files inside
      tmp/{tmpdir}/{name}/package/
    (no inner .tgz).  We repack those files as a proper npm .tgz and
    also save the raw .zip as a forensic artifact if save_dir is given.
    """
    # Try both subdirectories in order
    search_paths = [
        f"https://api.github.com/repos/{DATADOG_REPO}/contents/samples/npm/compromised_lib/{name}/{version}",
        f"https://api.github.com/repos/{DATADOG_REPO}/contents/samples/npm/malicious_intent/{name}/{version}",
    ]
    if dry_run:
        for p in search_paths:
            print(f"    [dry-run] GET {p}")
        return None

    listing = None
    for api_url in search_paths:
        result = _fetch_json(api_url, headers=_github_headers())
        if result and not (isinstance(result, dict) and result.get("message")):
            listing = result
            break
    if not listing:
        return None

    # Find a ZIP entry whose name contains the version
    zip_entry = None
    for item in listing:
        fname = item.get("name", "")
        if fname.endswith(".zip") and version in fname:
            zip_entry = item
            break
    if zip_entry is None:
        # Fallback: pick any .zip in the directory
        for item in listing:
            if item.get("name", "").endswith(".zip"):
                zip_entry = item
                break
    if zip_entry is None:
        return None

    download_url = zip_entry.get("download_url")
    if not download_url:
        # Large files use git LFS; fall back to raw URL
        download_url = zip_entry.get("html_url", "").replace(
            "https://github.com", "https://raw.githubusercontent.com"
        ).replace("/blob/", "/")
    if not download_url:
        return None

    print(f"    Downloading ZIP from Datadog GitHub: {zip_entry['name']}")
    zip_bytes = _fetch_bytes(download_url, headers=_github_headers(), timeout=60)
    if not zip_bytes:
        return None

    # Save raw ZIP as forensic artifact (original Datadog file)
    if save_dir and not dry_run:
        raw_zip_path = save_dir / zip_entry["name"]
        save_dir.mkdir(parents=True, exist_ok=True)
        raw_zip_path.write_bytes(zip_bytes)
        print(f"    Saved raw Datadog ZIP: {raw_zip_path.name} ({len(zip_bytes):,} bytes)")

    # Repack extracted package files → proper npm .tgz (all entries under package/ prefix)
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            # Find package root: directory that contains package.json
            pkg_prefix = None
            for n in zf.namelist():
                if n.endswith("/package.json") and n.count("/") >= 2:
                    pkg_prefix = n[: n.rfind("/") + 1]  # e.g. "tmp/tmpXXX/axios/package/"
                    break
            if pkg_prefix is None:
                print("    ⚠️  Could not find package.json inside ZIP")
                return None

            # Build npm-compatible .tgz in memory
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
                with tarfile.open(fileobj=gz, mode="w") as tar:
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        if not info.filename.startswith(pkg_prefix):
                            continue
                        rel = info.filename[len(pkg_prefix):]  # strip prefix → bare filename
                        tarinfo = tarfile.TarInfo(name=f"package/{rel}")
                        tarinfo.size = info.file_size
                        tar.addfile(tarinfo, io.BytesIO(zf.read(info.filename, pwd=b"infected")))
            return buf.getvalue()
    except Exception as e:
        print(f"    ⚠️  ZIP repack failed: {e}")
        return None


def try_npm_registry(name: str, version: str, dry_run: bool) -> bytes | None:
    url = f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"
    if dry_run:
        print(f"    [dry-run] GET {url}")
        return None
    print(f"    Trying npm registry: {url}")
    return _fetch_bytes(url, timeout=30)


def try_wayback_machine(name: str, version: str, dry_run: bool) -> bytes | None:
    target = f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"
    cdx_url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={urllib.parse.quote(target)}&output=json&limit=1&fl=timestamp"
    )
    if dry_run:
        print(f"    [dry-run] Wayback CDX: {cdx_url}")
        return None
    print(f"    Querying Wayback CDX for {name}@{version}...")
    result = _fetch_json(cdx_url)
    if not result or len(result) < 2:
        return None
    timestamp = result[1][0]
    wb_url = f"https://web.archive.org/web/{timestamp}if_/{target}"
    print(f"    Trying Wayback snapshot ({timestamp}): {wb_url}")
    return _fetch_bytes(wb_url, timeout=60)


# ── Main acquisition loop ─────────────────────────────────────────────────────

def acquire_package(pkg: dict, dry_run: bool, force: bool) -> dict:
    name = pkg["name"]
    version = pkg["version"]
    label = f"{name}@{version}"
    pkg_dir = EVIDENCE_DIR / label

    tgz_filename = f"{name}-{version}.tgz"
    tgz_path = pkg_dir / tgz_filename

    result = {
        "name": name,
        "version": version,
        "status": "not_found",
        "sources_tried": [],
    }

    if not force and tgz_path.exists() and not dry_run:
        print(f"  ⏭️  {label}: already exists (use --force to re-download)")
        data = tgz_path.read_bytes()
        result.update({
            "status": "acquired",
            "source": "cached",
            "file": str(tgz_path),
            "sha256": sha256_of(data),
            "sha1": sha1_of(data),
            "file_size_bytes": len(data),
        })
        _annotate_known_hashes(result)
        return result

    strategies = [
        ("datadog_github", try_datadog_github),
        ("npm_registry", try_npm_registry),
        ("wayback_machine", try_wayback_machine),
    ]

    tarball: bytes | None = None
    source_used: str | None = None

    for source_name, fn in strategies:
        result["sources_tried"].append(source_name)
        print(f"  → [{label}] trying {source_name}...")
        try:
            if source_name == "datadog_github":
                data = fn(name, version, dry_run, save_dir=pkg_dir)
            else:
                data = fn(name, version, dry_run)
        except Exception as e:
            print(f"    ⚠️  {source_name} error: {e}")
            data = None

        if data:
            tarball = data
            source_used = source_name
            break

    if dry_run:
        print(f"  ℹ️  {label}: dry-run complete (would try {', '.join(result['sources_tried'])})")
        result["status"] = "dry_run"
        return result

    if tarball is None:
        print(f"  ❌ {label}: not found in any source")
        result["note"] = "Could not acquire from any source"
        return result

    # Save to evidence directory
    if not dry_run:
        pkg_dir.mkdir(parents=True, exist_ok=True)
        tgz_path.write_bytes(tarball)

    file_sha256 = sha256_of(tarball)
    file_sha1 = sha1_of(tarball)

    # Write sidecar files
    (pkg_dir / "sha256.txt").write_text(f"{file_sha256}  {tgz_filename}\n")
    (pkg_dir / "sha1.txt").write_text(f"{file_sha1}  {tgz_filename}\n")

    acquired_at = datetime.now(timezone.utc).isoformat()
    metadata = {
        "name": name,
        "version": version,
        "source": source_used,
        "acquired_at": acquired_at,
        "file": tgz_filename,
        "sha256": file_sha256,
        "sha1": file_sha1,
        "file_size_bytes": len(tarball),
    }
    (pkg_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")

    result.update({
        "status": "acquired",
        "source": source_used,
        "acquired_at": acquired_at,
        "file": str(tgz_path),
        "sha256": file_sha256,
        "sha1": file_sha1,
        "file_size_bytes": len(tarball),
    })
    _annotate_known_hashes(result)

    # Hash match check
    key = label
    known = KNOWN_HASHES.get(key, {})
    if known.get("sha1") and known["sha1"] != file_sha1:
        print(f"  ⚠️  {label}: SHA1 MISMATCH  got={file_sha1}  expected={known['sha1']}")
        result["hash_match"] = "mismatch"
    elif known.get("sha1"):
        print(f"  ✅ {label}: acquired from {source_used}  SHA1 verified")
        result["hash_match"] = "match"
    else:
        print(f"  ✅ {label}: acquired from {source_used}  (no reference hash to verify)")

    return result


def _annotate_known_hashes(result: dict):
    key = f"{result['name']}@{result['version']}"
    known = KNOWN_HASHES.get(key)
    if known:
        result["known_hashes"] = known
    else:
        result["known_hashes"] = {"note": "No SANS-published reference hash available"}


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Preserve malicious npm packages as forensic evidence")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be attempted, don't download")
    parser.add_argument("--force", action="store_true", help="Re-download even if already exists")
    args = parser.parse_args()

    if not args.dry_run:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if not GITHUB_TOKEN:
        print("ℹ️  GITHUB_TOKEN not set — GitHub API rate limit is 60 req/hr (unauthenticated)")
    else:
        print("✅ GITHUB_TOKEN found — using authenticated GitHub API")

    print(f"\n{'[DRY RUN] ' if args.dry_run else ''}Preserving {len(MALICIOUS_PACKAGES)} malicious packages...\n")

    packages_report = []
    for pkg in MALICIOUS_PACKAGES:
        label = f"{pkg['name']}@{pkg['version']}"
        print(f"📦 {label}")
        entry = acquire_package(pkg, dry_run=args.dry_run, force=args.force)
        packages_report.append(entry)
        print()

    if args.dry_run:
        print("[dry-run] No files written.")
        return

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "packages": packages_report,
    }
    manifest_path = REPORTS_DIR / "evidence-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(f"📄 Manifest written: {manifest_path}")

    acquired = sum(1 for p in packages_report if p["status"] == "acquired")
    not_found = sum(1 for p in packages_report if p["status"] == "not_found")
    print(f"\nSummary: {acquired} acquired, {not_found} not found")


if __name__ == "__main__":
    main()
