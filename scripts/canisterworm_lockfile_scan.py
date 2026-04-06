#!/usr/bin/env python3
"""
CanisterWorm Lockfile Scanner
==============================
Uses XEIZE git credentials to fetch lockfiles from npm projects
and check for CanisterWorm malicious packages/versions.
"""

import json
import os
import ssl
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_AXIOS_DIR = os.path.join(ROOT_DIR, "internal", "reports", "axios")
LOCKFILE_REPORT_PATH = os.path.join(REPORTS_AXIOS_DIR, "canisterworm-lockfile-report.md")
IMPACT_REPORT_PATH = os.path.join(REPORTS_AXIOS_DIR, "canisterworm-impact-report.md")
DEFAULT_XEIZE_BASE_URL = "https://xeize.example/open-api/v1"

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_env(path=os.path.join(ROOT_DIR, ".env")):
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())

load_env()

API_KEY = os.environ.get("XEIZE_API_KEY", "")
BASE_URL = os.environ.get("XEIZE_BASE_URL", DEFAULT_XEIZE_BASE_URL)

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# CanisterWorm malicious packages with known bad versions
MALICIOUS_PACKAGES = {
    "@emilgroup/account-sdk": ["1.41.1", "1.41.2"],
    "@emilgroup/account-sdk-node": ["1.40.1", "1.40.2"],
    "@emilgroup/accounting-sdk-node": ["1.26.1", "1.26.2"],
    "@emilgroup/api-documentation": ["1.19.1", "1.19.2"],
    "@emilgroup/auth-sdk": ["1.25.1", "1.25.2"],
    "@emilgroup/auth-sdk-node": ["1.21.1", "1.21.2"],
    "@emilgroup/billing-sdk": ["1.56.1", "1.56.2"],
    "@emilgroup/billing-sdk-node": ["1.57.1", "1.57.2"],
    "@emilgroup/claim-sdk": ["1.41.1", "1.41.2"],
    "@emilgroup/claim-sdk-node": ["1.39.1", "1.39.2"],
    "@emilgroup/customer-sdk": ["1.54.1", "1.54.2"],
    "@emilgroup/customer-sdk-node": ["1.55.1", "1.55.2"],
    "@emilgroup/document-sdk": ["1.45.1", "1.45.2"],
    "@emilgroup/document-sdk-node": ["1.43.1", "1.43.2"],
    "@emilgroup/gdv-sdk": ["2.6.1", "2.6.2"],
    "@emilgroup/insurance-sdk": ["1.97.1", "1.97.2"],
    "@emilgroup/insurance-sdk-node": ["1.95.1", "1.95.2"],
    "@emilgroup/notification-sdk-node": ["1.4.1", "1.4.2"],
    "@emilgroup/partner-portal-sdk-node": ["1.1.1", "1.1.2"],
    "@emilgroup/partner-sdk-node": ["1.19.1", "1.19.2"],
    "@emilgroup/payment-sdk": ["1.15.1", "1.15.2"],
    "@emilgroup/payment-sdk-node": ["1.23.1", "1.23.2"],
    "@emilgroup/process-manager-sdk-node": ["1.13.1", "1.13.2"],
    "@emilgroup/public-api-sdk": ["1.33.1", "1.33.2"],
    "@emilgroup/public-api-sdk-node": ["1.35.1", "1.35.2"],
    "@emilgroup/tenant-sdk": ["1.34.1", "1.34.2"],
    "@emilgroup/tenant-sdk-node": ["1.33.1", "1.33.2"],
    "@emilgroup/translation-sdk-node": ["1.1.1", "1.1.2"],
    "@emilgroup/commission-sdk": ["1.0.2"],
    "@emilgroup/discount-sdk": ["1.5.1"],
    "@emilgroup/document-uploader": ["0.0.10"],
    "@emilgroup/docxtemplater-util": ["1.1.2"],
    "@emilgroup/numbergenerator-sdk-node": ["1.3.1"],
    "@emilgroup/partner-portal-sdk": ["1.1.1"],
    "@emilgroup/setting-sdk": ["0.2.2"],
    "@emilgroup/task-sdk": ["1.0.2"],
    "@emilgroup/task-sdk-node": ["1.0.3"],
    "@opengov/form-renderer": ["0.2.20"],
    "@opengov/ppf-backend-types": ["1.141.2"],
    "@teale.io/eslint-config": ["1.8.9", "1.8.10"],
    "@airtm/uuid-base32": ["1.0.2"],
    "@pypestream/floating-ui-dom": ["2.15.1"],
}

# Also check for any usage of these packages (even non-malicious versions = risk)
MALICIOUS_PACKAGE_NAMES = set(MALICIOUS_PACKAGES.keys())

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def api_get(endpoint, params=None):
    url = f"{BASE_URL}/{endpoint.lstrip('/')}"
    if params:
        qs = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
        if qs:
            url += f"?{qs}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {API_KEY}"})
    with urllib.request.urlopen(req, context=SSL_CTX) as resp:
        return json.loads(resp.read())


def get_git_credentials(project_id):
    """Get git URL and PAT for a project."""
    try:
        return api_get("git/credentials", {"project_id": project_id})
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

BITBUCKET_SERVER = "https://code.skplanet.com"


def fetch_file_from_bitbucket(repo, pat, branch, filepath):
    """Fetch a raw file from Bitbucket Server REST API."""
    parts = repo.split("/")
    if len(parts) != 2:
        return None
    proj_key, repo_slug = parts[0], parts[1]
    ref = branch or "master"

    url = (f"{BITBUCKET_SERVER}/rest/api/1.0/projects/{proj_key}"
           f"/repos/{repo_slug}/raw/{filepath}?at=refs/heads/{ref}")
    try:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {pat}"})
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def check_lockfile_content(content, filename):
    """Check lockfile content for CanisterWorm packages."""
    findings = []

    if not content:
        return findings

    content_lower = content.lower()

    for pkg_name, bad_versions in MALICIOUS_PACKAGES.items():
        if pkg_name.lower() in content_lower:
            # Package found in lockfile - check version
            version_hit = False
            for ver in bad_versions:
                if ver in content:
                    findings.append({
                        "package": pkg_name,
                        "version": ver,
                        "malicious_version": True,
                        "file": filename,
                    })
                    version_hit = True

            if not version_hit:
                # Package exists but not a known malicious version
                findings.append({
                    "package": pkg_name,
                    "version": "(non-malicious version)",
                    "malicious_version": False,
                    "file": filename,
                })

    return findings

# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("  CanisterWorm Lockfile Scanner")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    # Load npm projects
    with open("/tmp/npm_projects.json") as f:
        projects = json.load(f)

    print(f"\n[1/3] Loading {len(projects)} npm projects...")

    # Get git credentials and scan lockfiles
    print(f"\n[2/3] Fetching lockfiles and scanning for CanisterWorm packages...\n")

    results = []
    errors = []
    scanned = 0

    lockfiles = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]

    for i, proj in enumerate(projects):
        pid = proj["id"]
        name = proj["name"]
        branch = proj.get("branch")
        repo = proj.get("repository", "")
        integration_id = proj.get("integrationId")

        print(f"  [{i+1}/{len(projects)}] {name}", end="", flush=True)

        if not integration_id:
            print(" — skipped (no integration)")
            errors.append({"project": name, "error": "no integration (manual upload)"})
            continue

        creds = get_git_credentials(pid)
        if not creds:
            print(" — skipped (no credentials)")
            errors.append({"project": name, "error": "credentials unavailable"})
            continue

        git_url = creds.get("gitUrl", "")
        pat = creds.get("personalAccessToken", "")

        if not git_url or not pat:
            print(" — skipped (incomplete credentials)")
            errors.append({"project": name, "error": "incomplete credentials"})
            continue

        project_findings = []
        lockfile_found = False

        for lockfile in lockfiles:
            content = fetch_file_from_bitbucket(repo, pat, branch, lockfile)
            if content:
                lockfile_found = True
                findings = check_lockfile_content(content, lockfile)
                project_findings.extend(findings)

        if lockfile_found:
            scanned += 1
            if project_findings:
                mal_count = sum(1 for f in project_findings if f["malicious_version"])
                ref_count = sum(1 for f in project_findings if not f["malicious_version"])
                status = f"🚨 {mal_count} MALICIOUS" if mal_count else f"⚠️ {ref_count} refs"
                print(f" — {status}")
            else:
                print(" — ✅ clean")
        else:
            print(" — no lockfile found")
            errors.append({"project": name, "error": "no lockfile found"})

        results.append({
            "project": name,
            "repository": repo,
            "branch": branch,
            "findings": project_findings,
        })

    # Generate report
    print(f"\n[3/3] Generating report...")
    print(f"  Scanned: {scanned}/{len(projects)} projects")

    report = generate_lockfile_report(results, errors, scanned, len(projects))

    os.makedirs(REPORTS_AXIOS_DIR, exist_ok=True)
    report_path = LOCKFILE_REPORT_PATH
    with open(report_path, "w") as f:
        f.write(report)

    with open(IMPACT_REPORT_PATH, "a") as f:
        f.write("\n\n" + report)

    print(f"\n✅ Report saved: {report_path}")
    print(f"   Also appended to: {IMPACT_REPORT_PATH}")


def generate_lockfile_report(results, errors, scanned, total):
    lines = []
    w = lines.append

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    w("---")
    w("")
    w("# CanisterWorm Lockfile 직접 스캔 결과")
    w("")
    w(f"> **스캔 시각:** {now}")
    w(f"> **대상:** npm 사용 프로젝트 {total}개 중 lockfile 확인 {scanned}개")
    w("")

    # Categorize
    malicious_projects = []
    reference_projects = []
    clean_projects = []

    for r in results:
        if not r["findings"]:
            clean_projects.append(r)
        elif any(f["malicious_version"] for f in r["findings"]):
            malicious_projects.append(r)
        else:
            reference_projects.append(r)

    w("## 스캔 요약")
    w("")
    w("| 항목 | 수치 |")
    w("|---|---|")
    w(f"| 스캔 프로젝트 | {scanned}개 |")
    w(f"| 🚨 악성 버전 사용 | {len(malicious_projects)}개 |")
    w(f"| ⚠️ 패키지 참조 (비악성 버전) | {len(reference_projects)}개 |")
    w(f"| ✅ 클린 | {len(clean_projects)}개 |")
    w(f"| 스캔 실패/건너뜀 | {len(errors)}개 |")
    w("")

    # Critical: Malicious versions found
    if malicious_projects:
        w("## 🚨 악성 버전 사용 프로젝트 (즉시 조치 필요)")
        w("")
        for r in malicious_projects:
            w(f"### {r['project']}")
            w(f"- Repository: `{r['repository']}` (branch: `{r['branch']}`)")
            w("")
            w("| 패키지 | 버전 | 악성여부 | lockfile |")
            w("|---|---|---|---|")
            for f in r["findings"]:
                status = "🚨 **악성**" if f["malicious_version"] else "참조"
                w(f"| `{f['package']}` | `{f['version']}` | {status} | {f['file']} |")
            w("")
            w("**즉시 조치:**")
            w("1. 해당 패키지 즉시 제거 또는 안전한 버전으로 교체")
            w("2. 3/19~23 사이 빌드 이력 확인 → 있으면 모든 시크릿 교체")
            w("3. 빌드 서버 IOC 점검 (`pgmon` 서비스, `/tmp/pglog`)")
            w("")

    # Warning: Package references (non-malicious versions)
    if reference_projects:
        w("## ⚠️ CanisterWorm 대상 패키지 참조 (비악성 버전)")
        w("")
        w("이 프로젝트들은 CanisterWorm 공격 대상 패키지를 사용하지만, 현재 악성 버전은 아닙니다.")
        w("그러나 패키지 업데이트 시 감염 위험이 있으므로 lockfile 고정을 확인하세요.")
        w("")
        w("| 프로젝트 | 패키지 | lockfile |")
        w("|---|---|---|")
        for r in reference_projects:
            for f in r["findings"]:
                w(f"| {r['project']} | `{f['package']}` | {f['file']} |")
        w("")

    # Errors
    if errors:
        w("## 스캔 실패/건너뜀")
        w("")
        w("| 프로젝트 | 사유 |")
        w("|---|---|")
        for e in errors:
            w(f"| {e['project']} | {e['error']} |")
        w("")

    return "\n".join(lines)


if __name__ == "__main__":
    main()
