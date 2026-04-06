#!/usr/bin/env python3
"""
Full Bitbucket Lockfile Scanner for axios@1.14.1 / 0.30.4
==========================================================
Scans ALL 7,199 Bitbucket repos for axios supply chain compromise.
Also checks for CanisterWorm packages and plain-crypto-js.

After reading each lockfile, fetches package.json and evaluates whether the
declared axios range (^, ~, >=, etc.) could still resolve to a malicious
patch even when the lockfile pins a safe version (CI / fresh install risk).
"""

import json
import os
import re
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bitbucket_workspace import is_personal_workspace_repo
import urllib.request
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent.parent
INTERNAL_REPORTS_DIR = ROOT_DIR / "internal" / "reports"
REPORTS_DATA_DIR = INTERNAL_REPORTS_DIR / "data"
AXIOS_REPORTS_DIR = INTERNAL_REPORTS_DIR / "axios"
SCAN_JSON_PATH = REPORTS_DATA_DIR / "bitbucket-full-scan-result.json"
SCAN_MD_PATH = AXIOS_REPORTS_DIR / "bitbucket-full-scan-report.md"
DEFAULT_XEIZE_BASE_URL = "https://xeize.example/open-api/v1"


def load_env(path=ROOT_DIR / ".env"):
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
BB = "https://code.skplanet.com"

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

LOCKFILES = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]

# axios malicious versions
AXIOS_BAD = {"1.14.1", "0.30.4"}

# CanisterWorm packages (name only — any version = flag)
CANISTERWORM_PKGS = {
    "@emilgroup/account-sdk", "@emilgroup/account-sdk-node",
    "@emilgroup/accounting-sdk-node", "@emilgroup/billing-sdk",
    "@emilgroup/billing-sdk-node", "@emilgroup/claim-sdk",
    "@emilgroup/customer-sdk", "@emilgroup/document-sdk",
    "@emilgroup/insurance-sdk", "@emilgroup/payment-sdk",
    "@emilgroup/public-api-sdk", "@emilgroup/tenant-sdk",
    "@emilgroup/task-sdk", "@opengov/form-renderer",
    "@opengov/ppf-backend-types", "@teale.io/eslint-config",
    "@airtm/uuid-base32", "@pypestream/floating-ui-dom",
}

# ---------------------------------------------------------------------------
# npm semver (subset): can malicious axios land in this package.json range?
# Lockfile pins a snapshot; ^1.14.0 still allows 1.14.1 on the next npm install / CI.
# ---------------------------------------------------------------------------

def _tuple_ver(s):
    s = s.strip().lstrip('v').strip('"\'')
    s = re.split(r'[-+]', s, maxsplit=1)[0]
    parts = s.split('.')
    nums = []
    for p in parts[:3]:
        m = re.match(r'^(\d+)', p)
        nums.append(int(m.group(1)) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])


def _caret_includes(version: str, rest: str) -> bool:
    vt = _tuple_ver(version)
    low = _tuple_ver(rest)
    if vt < low:
        return False
    major = low[0]
    if major >= 1:
        high = (major + 1, 0, 0)
    elif major == 0 and low[1] >= 1:
        high = (0, low[1] + 1, 0)
    else:
        high = (0, 0, low[2] + 1)
    return vt < high


def _tilde_includes(version: str, rest: str) -> bool:
    vt = _tuple_ver(version)
    low = _tuple_ver(rest)
    high = (low[0], low[1] + 1, 0)
    return low <= vt < high


def _npm_range_includes_version(version: str, spec: str) -> bool:
    """True if npm dependency range `spec` could resolve to `version` (npm semver subset)."""
    spec_orig = spec
    spec = spec.strip().strip('"\'')
    if not spec:
        return False
    low_spec = spec_orig.lower()
    if low_spec.startswith("workspace:") or low_spec.startswith("file:") or low_spec.startswith("link:"):
        return False
    if spec in ("*", "latest", "x"):
        return True
    if "||" in spec:
        return any(_npm_range_includes_version(version, p.strip()) for p in spec.split("||"))

    if " - " in spec:
        lo, hi = [x.strip() for x in spec.split(" - ", 1)]
        vt = _tuple_ver(version)
        return _tuple_ver(lo) <= vt <= _tuple_ver(hi)

    m = re.match(r"^>=\s*(\S+)\s+<\s*(\S+)$", spec)
    if m:
        lo, hi = m.group(1), m.group(2)
        vt = _tuple_ver(version)
        return _tuple_ver(lo) <= vt < _tuple_ver(hi)

    if spec.startswith("^"):
        return _caret_includes(version, spec[1:])
    if spec.startswith("~"):
        return _tilde_includes(version, spec[1:])
    if spec.startswith(">="):
        return _tuple_ver(version) >= _tuple_ver(spec[2:].strip())
    if spec.startswith("<="):
        return _tuple_ver(version) <= _tuple_ver(spec[2:].strip())
    if spec.startswith(">"):
        return _tuple_ver(version) > _tuple_ver(spec[1:].strip())
    if spec.startswith("<"):
        return _tuple_ver(version) < _tuple_ver(spec[1:].strip())
    if spec.startswith("="):
        return _tuple_ver(version) == _tuple_ver(spec[1:].strip())

    m = re.match(r"^(\d+)\.(\d+)\.[xX*]$", spec)
    if m:
        maj, mino = int(m.group(1)), int(m.group(2))
        vt = _tuple_ver(version)
        return vt[0] == maj and vt[1] == mino
    m = re.match(r"^(\d+)\.[xX*]$", spec)
    if m:
        maj = int(m.group(1))
        vt = _tuple_ver(version)
        return vt[0] == maj

    if re.match(r"^[\dv][\d.]*$", spec.lstrip("v")):
        return _tuple_ver(version) == _tuple_ver(spec)

    return False


def package_json_axios_semver_bad_hits(spec: str):
    """Which of AXIOS_BAD can satisfy this declared range."""
    hits = []
    for bad in AXIOS_BAD:
        if _npm_range_includes_version(bad, spec):
            hits.append(bad)
    return hits


def check_package_json_axios(content: str):
    """Parse package.json for axios dependency; return (declared_spec_or_None, bad_versions_range_allows)."""
    try:
        pkg = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return None, []

    spec_out = None
    bad_union = []
    dep_sections = (
        "dependencies", "devDependencies", "optionalDependencies", "peerDependencies"
    )
    for sec in dep_sections:
        deps = pkg.get(sec) or {}
        raw = deps.get("axios")
        if raw is None:
            continue
        if isinstance(raw, str):
            spec = raw.strip()
        elif isinstance(raw, dict):
            spec = (raw.get("version") or "").strip()
            if not spec:
                spec = str(raw)
        else:
            spec = str(raw).strip()

        if not spec_out:
            spec_out = spec
        for b in package_json_axios_semver_bad_hits(spec):
            if b not in bad_union:
                bad_union.append(b)

    return spec_out, bad_union


def enrich_from_package_json(result: dict, pk: str, slug: str):
    """Fetch package.json and attach semver-range risk (next install / CI)."""
    try:
        pj = bb_raw(pk, slug, "package.json")
    except Exception:
        return
    spec, bad_hits = check_package_json_axios(pj)
    if spec:
        result["axios_package_json_spec"] = spec
    if bad_hits:
        result["axios_semver_can_resolve_bad"] = bad_hits


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

PAT = None

def get_pat():
    global PAT
    if PAT:
        return PAT
    url = f"{BASE_URL}/projects"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {API_KEY}"})
    with urllib.request.urlopen(req, context=SSL_CTX) as r:
        projects = json.loads(r.read())
    for p in projects:
        if p.get("integrationId"):
            try:
                cred_url = f"{BASE_URL}/git/credentials?project_id={p['id']}"
                req2 = urllib.request.Request(cred_url, headers={"Authorization": f"Bearer {API_KEY}"})
                with urllib.request.urlopen(req2, context=SSL_CTX) as r2:
                    creds = json.loads(r2.read())
                    PAT = creds.get("personalAccessToken")
                    if PAT:
                        return PAT
            except:
                pass
    sys.exit("ERROR: Could not obtain Bitbucket PAT")


def bb_get(path, timeout=15):
    url = f"{BB}/rest/api/1.0/{path}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {get_pat()}"})
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=timeout) as r:
        return json.loads(r.read())


def bb_raw(project_key, repo_slug, filepath, branch=None):
    ref = f"?at=refs/heads/{branch}" if branch else ""
    url = f"{BB}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}/raw/{filepath}{ref}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {get_pat()}"})
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=60) as r:
        return r.read().decode("utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Scan logic
# ---------------------------------------------------------------------------

def get_all_repos():
    repos = []
    start = 0
    while True:
        data = bb_get(f"repos?limit=1000&start={start}")
        for r in data.get("values", []):
            proj = r.get("project", {})
            repos.append({
                "project_key": proj.get("key", ""),
                "slug": r.get("slug", ""),
                "name": f"{proj.get('key','')}/{r.get('slug','')}",
            })
        if data.get("isLastPage", True):
            break
        start = data.get("nextPageStart", start + 1000)
    return repos


def check_axios_in_package_lock(content):
    """Parse package-lock.json and extract actual axios version."""
    try:
        lock = json.loads(content)
    except:
        return None, []

    findings = []

    # lockfileVersion 2/3: packages
    pkgs = lock.get("packages", {})
    axios_ver = None
    for pkg_path, pkg_info in pkgs.items():
        if pkg_path.endswith("/axios") or pkg_path == "axios":
            axios_ver = pkg_info.get("version")
            if axios_ver in AXIOS_BAD:
                findings.append(f"axios@{axios_ver}")
            # Check if plain-crypto-js is in its dependencies
            deps = pkg_info.get("dependencies", {})
            if "plain-crypto-js" in deps:
                findings.append("plain-crypto-js (axios dep)")

        # Check for plain-crypto-js anywhere
        if pkg_path.endswith("/plain-crypto-js") or "plain-crypto-js" in pkg_path:
            findings.append(f"plain-crypto-js@{pkg_info.get('version','?')}")

        # Check for canisterworm packages
        for cw_pkg in CANISTERWORM_PKGS:
            if pkg_path.endswith(f"/{cw_pkg}"):
                findings.append(f"canisterworm:{cw_pkg}@{pkg_info.get('version','?')}")

    # lockfileVersion 1: dependencies
    if not axios_ver:
        deps = lock.get("dependencies", {})
        if "axios" in deps:
            axios_ver = deps["axios"].get("version")
            if axios_ver in AXIOS_BAD:
                findings.append(f"axios@{axios_ver}")
        if "plain-crypto-js" in deps:
            findings.append(f"plain-crypto-js@{deps['plain-crypto-js'].get('version','?')}")

    return axios_ver, findings


def check_yarn_lock(content):
    """Check yarn.lock for axios bad versions."""
    findings = []
    axios_ver = None

    for block in content.split("\n\n"):
        lines = block.strip().split("\n")
        if not lines:
            continue
        header = lines[0]

        if "axios@" in header or '"axios@' in header:
            for line in lines[1:]:
                line = line.strip()
                if line.startswith("version"):
                    ver = line.split('"')[1] if '"' in line else line.split()[-1]
                    axios_ver = ver
                    if ver in AXIOS_BAD:
                        findings.append(f"axios@{ver}")

        if "plain-crypto-js" in header:
            for line in lines[1:]:
                line = line.strip()
                if line.startswith("version"):
                    ver = line.split('"')[1] if '"' in line else line.split()[-1]
                    findings.append(f"plain-crypto-js@{ver}")

    return axios_ver, findings


def check_pnpm_lock(content):
    """Check pnpm-lock.yaml for axios bad versions."""
    import re
    findings = []
    axios_ver = None

    # pnpm-lock: /axios@version or axios: version
    for m in re.finditer(r'/axios[@/](\d+\.\d+\.\d+)', content):
        ver = m.group(1)
        axios_ver = ver
        if ver in AXIOS_BAD:
            findings.append(f"axios@{ver}")

    if re.search(r'plain-crypto-js', content):
        findings.append("plain-crypto-js found")

    return axios_ver, findings


def scan_repo(repo):
    """Scan a single repo. Returns (repo_name, axios_ver, lockfile, findings) or None."""
    pk = repo["project_key"]
    slug = repo["slug"]
    name = repo["name"]

    for lf in LOCKFILES:
        try:
            content = bb_raw(pk, slug, lf)
        except:
            continue

        if not content or len(content) < 10:
            continue

        if lf == "package-lock.json":
            axios_ver, findings = check_axios_in_package_lock(content)
        elif lf == "yarn.lock":
            axios_ver, findings = check_yarn_lock(content)
        elif lf == "pnpm-lock.yaml":
            axios_ver, findings = check_pnpm_lock(content)
        else:
            continue

        result = {
            "name": name,
            "axios_ver": axios_ver,
            "lockfile": lf,
            "findings": list(findings),
            "has_lockfile": True,
        }
        enrich_from_package_json(result, pk, slug)
        return result

    return {"name": name, "has_lockfile": False}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("  Full Bitbucket axios Supply Chain Scan")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    print("\n[1/3] Listing all Bitbucket repos...")
    repos_all = get_all_repos()
    personal_n = sum(1 for r in repos_all if is_personal_workspace_repo(r.get("name", "")))
    repos = [r for r in repos_all if not is_personal_workspace_repo(r.get("name", ""))]
    print(
        f"  → 전체 {len(repos_all)}개, 개인 워크스페이스(~…) {personal_n}개 제외 → 스캔 대상 {len(repos)}개"
    )

    print(f"\n[2/3] Scanning lockfiles ({len(LOCKFILES)} types) with 10 threads...")
    print(f"  This will take a while...\n")

    results_with_lockfile = []
    results_with_axios = []
    results_with_findings = []
    no_lockfile = 0
    errors = 0
    scanned = 0

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(scan_repo, r): r for r in repos}
        for future in as_completed(futures):
            scanned += 1
            try:
                result = future.result()
            except Exception as e:
                errors += 1
                if scanned % 500 == 0:
                    print(f"  [{scanned}/{len(repos)}] ... (lockfiles: {len(results_with_lockfile)}, axios: {len(results_with_axios)}, findings: {len(results_with_findings)}, errors: {errors})")
                continue

            if not result.get("has_lockfile"):
                no_lockfile += 1
            else:
                results_with_lockfile.append(result)
                if result.get("axios_ver"):
                    results_with_axios.append(result)
                if result.get("findings"):
                    results_with_findings.append(result)
                    print(f"  🚨 {result['name']} → {result['findings']}")

            if scanned % 500 == 0:
                print(f"  [{scanned}/{len(repos)}] ... (lockfiles: {len(results_with_lockfile)}, axios: {len(results_with_axios)}, findings: {len(results_with_findings)}, errors: {errors})")

    print(f"\n  [{scanned}/{len(repos)}] DONE")

    # Summary
    print(f"\n[3/3] Results")
    print(f"  Total repos:          {len(repos)}")
    print(f"  With lockfile:        {len(results_with_lockfile)}")
    print(f"  Using axios:          {len(results_with_axios)}")
    print(f"  With FINDINGS:        {len(results_with_findings)}")
    semver_range_risk = sum(1 for r in results_with_axios if r.get("axios_semver_can_resolve_bad"))
    print(f"  package.json semver may hit bad patch: {semver_range_risk}")
    print(f"  No lockfile:          {no_lockfile}")
    print(f"  Errors:               {errors}")

    if results_with_findings:
        print(f"\n  === FINDINGS ===")
        for r in results_with_findings:
            print(f"  🚨 {r['name']:50s} axios={r.get('axios_ver','n/a'):10s} {r['findings']}")

    def _axios_row(r):
        row = {
            "name": r["name"],
            "version": r["axios_ver"],
            "lockfile": r["lockfile"],
        }
        if r.get("axios_package_json_spec"):
            row["axios_package_json_spec"] = r["axios_package_json_spec"]
        if r.get("axios_semver_can_resolve_bad"):
            row["axios_semver_can_resolve_bad"] = r["axios_semver_can_resolve_bad"]
        if r.get("findings"):
            row["findings"] = r["findings"]
        return row

    REPORTS_DATA_DIR.mkdir(parents=True, exist_ok=True)
    AXIOS_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Save results
    report = {
        "scan_time": datetime.now().isoformat(),
        "total_repos": len(repos),
        "personal_workspace_excluded": personal_n,
        "with_lockfile": len(results_with_lockfile),
        "using_axios": len(results_with_axios),
        "findings_count": len(results_with_findings),
        "semver_range_risk_count": semver_range_risk,
        "findings": results_with_findings,
        "axios_versions": sorted(
            [_axios_row(r) for r in results_with_axios],
            key=lambda x: x["version"] or "", reverse=True
        ),
    }

    with open(SCAN_JSON_PATH, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    # Markdown report
    md = generate_md_report(report, results_with_axios)
    with open(SCAN_MD_PATH, "w") as f:
        f.write(md)

    print(f"\n✅ Reports saved:")
    print(f"   {SCAN_JSON_PATH.relative_to(ROOT_DIR)}")
    print(f"   {SCAN_MD_PATH.relative_to(ROOT_DIR)}")


def generate_md_report(report, axios_repos):
    lines = []
    w = lines.append
    now = report["scan_time"]

    w("# Bitbucket 전체 리포지토리 axios 공급망 공격 스캔 결과")
    w("")
    w(f"> **스캔 시각:** {now}")
    w(f"> **대상:** Bitbucket 전체 {report['total_repos']}개 리포지토리")
    w("")
    w("## 스캔 요약")
    w("")
    w("| 항목 | 수치 |")
    w("|---|---|")
    w(f"| 전체 리포지토리 | {report['total_repos']}개 |")
    pe = report.get("personal_workspace_excluded")
    if pe is not None:
        w(f"| 제외(개인 ~… 워크스페이스, 스캔 안 함) | {pe}개 |")
    w(f"| lockfile 보유 | {report['with_lockfile']}개 |")
    w(f"| axios 사용 | {report['using_axios']}개 |")
    w(f"| 🚨 감염/위험 발견 | **{report['findings_count']}개** |")
    sr = report.get("semver_range_risk_count", 0)
    w(f"| ⚠️ package.json 범위가 악성 패치 포함 가능 | **{sr}개** |")
    w("")

    risk_rows = [r for r in axios_repos if r.get("axios_semver_can_resolve_bad")]
    if risk_rows:
        w("## ⚠️ package.json semver 범위 (lock과 악성 불일치 가능)")
        w("")
        w("lock은 **현재 resolve 스냅샷**만 고정한다. `^1.14.0` 같으면 이후 `npm install`/CI에서 **1.14.1로 올라갈 수 있다.**")
        w("")
        w("| 리포지토리 | lock axios | package.json 선언 | 악성 버전 포함 가능 |")
        w("|---|---|---|---|")
        for r in sorted(risk_rows, key=lambda x: x["name"]):
            spec = r.get("axios_package_json_spec", "?")
            bad = ", ".join(r["axios_semver_can_resolve_bad"])
            w(f"| {r['name']} | {r.get('axios_ver','?')} | `{spec}` | {bad} |")
        w("")

    if report["findings"]:
        w("## 🚨 발견 항목 (lockfile·기타)")
        w("")
        w("| 리포지토리 | axios 버전 | lockfile | 발견 내용 |")
        w("|---|---|---|---|")
        for f in report["findings"]:
            findings_str = ", ".join(f["findings"])
            w(f"| {f['name']} | {f.get('axios_ver','n/a')} | {f['lockfile']} | {findings_str} |")
        w("")
    elif not risk_rows:
        w("## ✅ lockfile 기준 악성 버전 미고정")
        w("")
        w("axios@1.14.1 / 0.30.4, plain-crypto-js, CanisterWorm 패키지가 lock에 직접 잡히지 않았다. semver 범위 행은 위 표 참고.")
        w("")
    else:
        w("## ✅ lockfile 기준 직접 악성 고정 없음")
        w("")
        w("다만 위 **package.json 범위** 행은 설치/CI 타이밍에 따라 악성 패치가 lock에 들어올 수 있으니 별도 확인 권장.")
        w("")

    # Top axios versions
    w("## axios 사용 현황 (버전별)")
    w("")
    ver_count = {}
    for r in axios_repos:
        v = r.get("axios_ver", "unknown")
        ver_count[v] = ver_count.get(v, 0) + 1

    w("| 버전 | 리포 수 | 안전여부 |")
    w("|---|---|---|")
    for v in sorted(ver_count.keys(), reverse=True):
        safe = "🚨 **악성**" if v in AXIOS_BAD else "✅"
        w(f"| {v} | {ver_count[v]}개 | {safe} |")
    w("")
    w("---")
    w("*Bitbucket REST API 기반 전수 스캔 결과*")

    return "\n".join(lines)


if __name__ == "__main__":
    main()
