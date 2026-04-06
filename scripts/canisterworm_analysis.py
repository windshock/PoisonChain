#!/usr/bin/env python3
"""
CanisterWorm Supply Chain Attack — XEIZE Impact Analysis
=========================================================
Queries XEIZE API to identify projects and vulnerabilities
potentially affected by the CanisterWorm campaign (2026-03-19 ~ 2026-03-23).

Cross-references with known malicious npm packages and enriches
CVE data with EPSS scores for prioritization.
"""

import os
import json
import urllib.request
import ssl
import sys
from datetime import datetime
from collections import defaultdict

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_AXIOS_DIR = os.path.join(ROOT_DIR, "internal", "reports", "axios")
DEFAULT_XEIZE_BASE_URL = "https://xeize.example/open-api/v1"

# ---------------------------------------------------------------------------
# Configuration
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

if not API_KEY:
    sys.exit("ERROR: XEIZE_API_KEY not set. Check .env file.")

# Attack window
ATTACK_START = "2026-03-19T00:00:00Z"
ATTACK_END   = "2026-03-23T23:59:59Z"

# Known CanisterWorm malicious packages (from checklist)
CANISTERWORM_PACKAGES = {
    # @emilgroup (37)
    "@emilgroup/account-sdk", "@emilgroup/account-sdk-node",
    "@emilgroup/accounting-sdk-node", "@emilgroup/api-documentation",
    "@emilgroup/auth-sdk", "@emilgroup/auth-sdk-node",
    "@emilgroup/billing-sdk", "@emilgroup/billing-sdk-node",
    "@emilgroup/claim-sdk", "@emilgroup/claim-sdk-node",
    "@emilgroup/customer-sdk", "@emilgroup/customer-sdk-node",
    "@emilgroup/document-sdk", "@emilgroup/document-sdk-node",
    "@emilgroup/gdv-sdk", "@emilgroup/insurance-sdk",
    "@emilgroup/insurance-sdk-node", "@emilgroup/notification-sdk-node",
    "@emilgroup/partner-portal-sdk-node", "@emilgroup/partner-sdk-node",
    "@emilgroup/payment-sdk", "@emilgroup/payment-sdk-node",
    "@emilgroup/process-manager-sdk-node", "@emilgroup/public-api-sdk",
    "@emilgroup/public-api-sdk-node", "@emilgroup/tenant-sdk",
    "@emilgroup/tenant-sdk-node", "@emilgroup/translation-sdk-node",
    "@emilgroup/commission-sdk", "@emilgroup/discount-sdk",
    "@emilgroup/document-uploader", "@emilgroup/docxtemplater-util",
    "@emilgroup/numbergenerator-sdk-node", "@emilgroup/partner-portal-sdk",
    "@emilgroup/setting-sdk", "@emilgroup/task-sdk",
    "@emilgroup/task-sdk-node",
    # @opengov (6)
    "@opengov/form-renderer", "@opengov/ppf-backend-types",
    "@opengov/ppf-eslint-config", "@opengov/form-utils",
    "@opengov/qa-record-types-api", "@opengov/form-builder",
    # Others (3)
    "@teale.io/eslint-config", "@airtm/uuid-base32",
    "@pypestream/floating-ui-dom",
}

# Substring match on vulnerability name/description/ruleId. Only campaign-specific
# tokens — generic phrases ("supply chain", "backdoor", …) match almost everything.
# Known-bad package names are handled separately via CANISTERWORM_PACKAGES.
IOC_KEYWORDS = [
    "canisterworm",
    "teampcp",
    "icp0.io",
    "pgmon",
    "tdtqy-oyaaa",
]

# Known trivy-action related patterns
TRIVY_KEYWORDS = ["trivy-action", "setup-trivy", "trivy"]

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

# Disable SSL verification for internal server
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

def api_get(endpoint, params=None):
    """GET request to XEIZE API."""
    url = f"{BASE_URL}/{endpoint.lstrip('/')}"
    if params:
        qs = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
        if qs:
            url += f"?{qs}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {API_KEY}"})
    with urllib.request.urlopen(req, context=SSL_CTX) as resp:
        return json.loads(resp.read())


def get_all_projects():
    """Fetch all projects."""
    return api_get("projects")


def get_vulnerabilities(page=1, page_size=100, **filters):
    """Fetch vulnerabilities with pagination and filters."""
    params = {"page": page, "pageSize": page_size}
    params.update(filters)
    return api_get("vulnerabilities", params)


def get_all_vulnerabilities(**filters):
    """Paginate through all vulnerabilities matching filters."""
    all_vulns = []
    page = 1
    while True:
        data = get_vulnerabilities(page=page, page_size=100, **filters)
        vulns = data.get("vulnerabilities", [])
        all_vulns.extend(vulns)
        total_pages = data.get("totalPages", 1)
        total_count = data.get("totalCount", 0)
        print(f"  ... fetched page {page}/{total_pages} ({len(all_vulns)}/{total_count})", end="\r")
        if page >= total_pages:
            break
        page += 1
    print()
    return all_vulns, data.get("totalCount", len(all_vulns))


def get_cve(cve_id):
    """Fetch CVE details with EPSS score."""
    try:
        return api_get(f"cves/{cve_id}")
    except Exception as e:
        return None

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def match_canisterworm(vuln):
    """Check if a vulnerability matches CanisterWorm IOCs."""
    name = (vuln.get("name") or "").lower()
    desc = (vuln.get("description") or "").lower()
    rule_id = (vuln.get("ruleId") or "").lower()
    combined = f"{name} {desc} {rule_id}"

    matches = []

    # Direct package name match
    for pkg in CANISTERWORM_PACKAGES:
        if pkg.lower() in combined:
            matches.append(f"package:{pkg}")

    # IOC keyword match
    for kw in IOC_KEYWORDS:
        if kw.lower() in combined:
            matches.append(f"ioc:{kw}")

    # Trivy-related (GitHub Actions attack vector)
    for kw in TRIVY_KEYWORDS:
        if kw.lower() in combined:
            matches.append(f"trivy:{kw}")

    return matches


def run_analysis():
    print("=" * 70)
    print("  CanisterWorm Impact Analysis — XEIZE")
    print(f"  Attack window: 2026-03-19 ~ 2026-03-23")
    print(f"  Scan time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("=" * 70)

    # ----- Step 1: Load projects -----
    print("\n[1/5] Fetching all projects...")
    projects = get_all_projects()
    project_map = {p["id"]: p for p in projects}
    print(f"  → {len(projects)} projects loaded")

    # ----- Step 2: Query attack-window vulnerabilities -----
    print("\n[2/5] Querying vulnerabilities detected during attack window (3/19-23)...")
    attack_vulns, attack_total = get_all_vulnerabilities(
        detectedFrom=ATTACK_START,
        detectedTo=ATTACK_END,
    )
    print(f"  → {attack_total} vulnerabilities detected in attack window")

    # ----- Step 3: Query all npm-source vulnerabilities (broader scan) -----
    print("\n[3/5] Querying npm-source vulnerabilities (CRITICAL + HIGH)...")
    npm_critical, npm_crit_total = get_all_vulnerabilities(
        severity="CRITICAL", status="OPEN",
    )
    npm_high, npm_high_total = get_all_vulnerabilities(
        severity="HIGH", status="OPEN",
    )
    print(f"  → CRITICAL: {npm_crit_total}, HIGH: {npm_high_total}")

    # ----- Step 4: Cross-reference with CanisterWorm IOCs -----
    print("\n[4/5] Cross-referencing with CanisterWorm IOCs...")

    all_candidate_vulns = {}
    for v in attack_vulns + npm_critical + npm_high:
        all_candidate_vulns[v["id"]] = v

    print(f"  → {len(all_candidate_vulns)} unique vulnerabilities to scan")

    direct_hits = []       # Direct CanisterWorm package matches
    ioc_hits = []          # IOC keyword matches
    trivy_hits = []        # Trivy-related
    attack_window_npm = [] # npm vulns in attack window (potential indicators)

    for vid, v in all_candidate_vulns.items():
        matches = match_canisterworm(v)
        if matches:
            pkg_matches = [m for m in matches if m.startswith("package:")]
            ioc_matches = [m for m in matches if m.startswith("ioc:")]
            trivy_matches = [m for m in matches if m.startswith("trivy:")]
            entry = {**v, "_matches": matches}
            if pkg_matches:
                direct_hits.append(entry)
            if ioc_matches:
                ioc_hits.append(entry)
            if trivy_matches:
                trivy_hits.append(entry)

        # npm vulns in attack window
        if v.get("source") == "npm" and v["id"] in {av["id"] for av in attack_vulns}:
            attack_window_npm.append(v)

    print(f"  → Direct package matches: {len(direct_hits)}")
    print(f"  → IOC keyword matches: {len(ioc_hits)}")
    print(f"  → Trivy-related: {len(trivy_hits)}")
    print(f"  → npm vulns in attack window: {len(attack_window_npm)}")

    # ----- Step 5: CVE enrichment for hits -----
    print("\n[5/5] Enriching CVE data for findings...")
    cve_cache = {}
    all_hits = {v["id"]: v for v in direct_hits + ioc_hits + trivy_hits}
    cve_ids_to_fetch = set()
    for v in all_hits.values():
        rid = v.get("ruleId") or ""
        if rid.startswith("CVE-"):
            cve_ids_to_fetch.add(rid)

    for i, cve_id in enumerate(cve_ids_to_fetch):
        print(f"  ... CVE {i+1}/{len(cve_ids_to_fetch)}: {cve_id}", end="\r")
        cve_data = get_cve(cve_id)
        if cve_data:
            cve_cache[cve_id] = cve_data
    if cve_ids_to_fetch:
        print()
    print(f"  → {len(cve_cache)} CVEs enriched")

    # ----- Generate Report -----
    print("\n" + "=" * 70)
    print("  Generating report...")
    print("=" * 70)

    report = generate_report(
        projects=project_map,
        direct_hits=direct_hits,
        ioc_hits=ioc_hits,
        trivy_hits=trivy_hits,
        attack_window_npm=attack_window_npm,
        attack_total=attack_total,
        cve_cache=cve_cache,
        total_projects=len(projects),
    )

    report_path = os.path.join(REPORTS_AXIOS_DIR, "canisterworm-impact-report.md")
    os.makedirs(REPORTS_AXIOS_DIR, exist_ok=True)
    with open(report_path, "w") as f:
        f.write(report)
    print(f"\n✅ Report saved: {report_path}")
    print(f"   Total findings: {len(direct_hits)} direct + {len(ioc_hits)} IOC + {len(trivy_hits)} trivy-related")

    return report


def generate_report(projects, direct_hits, ioc_hits, trivy_hits,
                    attack_window_npm, attack_total, cve_cache, total_projects):
    """Generate markdown impact assessment report."""

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = []
    w = lines.append

    w("# CanisterWorm 공급망 공격 — XEIZE 영향도 분석 보고서")
    w("")
    w(f"> **분석 시각:** {now}")
    w(f"> **공격 기간:** 2026-03-19 ~ 2026-03-23")
    w(f"> **위협 행위자:** TeamPCP")
    w(f"> **분석 대상:** XEIZE 등록 프로젝트 {total_projects}개")
    w("")

    # ── Executive Summary ──
    w("## 1. 요약 (Executive Summary)")
    w("")

    affected_projects = set()
    for v in direct_hits + ioc_hits + trivy_hits:
        affected_projects.add(v["projectId"])

    w(f"| 항목 | 수치 |")
    w(f"|---|---|")
    w(f"| 전체 분석 프로젝트 | {total_projects}개 |")
    w(f"| 공격 기간 탐지 취약점 | {attack_total}건 |")
    w(f"| CanisterWorm 직접 매칭 | {len(direct_hits)}건 |")
    w(f"| IOC 키워드 매칭 | {len(ioc_hits)}건 |")
    w(f"| Trivy 관련 | {len(trivy_hits)}건 |")
    w(f"| 공격 기간 npm 취약점 | {len(attack_window_npm)}건 |")
    w(f"| **영향 프로젝트** | **{len(affected_projects)}개** |")
    w("")

    # ── Direct Hits (Critical) ──
    w("## 2. 🚨 CanisterWorm 직접 매칭 (즉시 조치 필요)")
    w("")
    if direct_hits:
        # Group by project
        by_project = defaultdict(list)
        for v in direct_hits:
            by_project[v["projectId"]].append(v)

        for pid, vulns in sorted(by_project.items(), key=lambda x: -len(x[1])):
            proj = projects.get(pid, {})
            pname = proj.get("name", pid[:12])
            repo = proj.get("repository", "-")
            branch = proj.get("branch", "-")
            w(f"### 프로젝트: {pname}")
            w(f"- Repository: `{repo}` (branch: `{branch}`)")
            w(f"- 매칭 취약점: {len(vulns)}건")
            w("")
            w("| 심각도 | 취약점명 | 매칭 패키지 | 탐지일 | 상태 |")
            w("|---|---|---|---|---|")
            for v in sorted(vulns, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(x["severity"],5)):
                matches = ", ".join(m.replace("package:", "") for m in v.get("_matches", []) if m.startswith("package:"))
                detected = v.get("detectedAt", "")[:10]
                w(f"| {v['severity']} | {v['name'][:60]} | `{matches}` | {detected} | {v['status']} |")
            w("")
    else:
        w("✅ CanisterWorm 감염 패키지 직접 매칭 없음")
        w("")

    # ── IOC Matches ──
    w("## 3. ⚠️ IOC 키워드 매칭")
    w("")
    if ioc_hits:
        by_project = defaultdict(list)
        for v in ioc_hits:
            by_project[v["projectId"]].append(v)

        for pid, vulns in sorted(by_project.items(), key=lambda x: -len(x[1])):
            proj = projects.get(pid, {})
            pname = proj.get("name", pid[:12])
            w(f"### {pname}")
            w("")
            w("| 심각도 | 취약점명 | IOC 매칭 | 탐지일 |")
            w("|---|---|---|---|")
            for v in vulns:
                ioc_m = ", ".join(m.replace("ioc:", "") for m in v.get("_matches", []) if m.startswith("ioc:"))
                detected = v.get("detectedAt", "")[:10]
                w(f"| {v['severity']} | {v['name'][:60]} | {ioc_m} | {detected} |")
            w("")
    else:
        w("IOC 키워드 매칭 없음")
        w("")

    # ── Trivy Related ──
    w("## 4. 🔍 Trivy 관련 취약점 (GitHub Actions 공격 벡터)")
    w("")
    if trivy_hits:
        w("| 프로젝트 | 심각도 | 취약점명 | 탐지일 |")
        w("|---|---|---|---|")
        for v in trivy_hits:
            proj = projects.get(v["projectId"], {})
            pname = proj.get("name", v["projectId"][:12])
            detected = v.get("detectedAt", "")[:10]
            w(f"| {pname} | {v['severity']} | {v['name'][:60]} | {detected} |")
        w("")
    else:
        w("Trivy 관련 취약점 없음")
        w("")

    # ── Attack Window npm vulns (Top 30) ──
    w("## 5. 📋 공격 기간(3/19-23) npm 취약점 상위 목록")
    w("")
    if attack_window_npm:
        # Sort by severity then priority score
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_vulns = sorted(attack_window_npm,
                              key=lambda x: (sev_order.get(x["severity"], 5), -x.get("priorityScore", 0)))
        w(f"총 {len(attack_window_npm)}건 중 상위 30건:")
        w("")
        w("| # | 심각도 | 점수 | 취약점명 | 프로젝트 | 탐지일 |")
        w("|---|---|---|---|---|---|")
        for i, v in enumerate(sorted_vulns[:30], 1):
            proj = projects.get(v["projectId"], {})
            pname = proj.get("name", v["projectId"][:12])
            detected = v.get("detectedAt", "")[:10]
            w(f"| {i} | {v['severity']} | {v.get('priorityScore', '-')} | {v['name'][:50]} | {pname[:30]} | {detected} |")
        w("")
    else:
        w("공격 기간 중 npm 관련 취약점 없음")
        w("")

    # ── CVE Enrichment ──
    if cve_cache:
        w("## 6. 📊 CVE 상세 (EPSS 기반 악용 가능성)")
        w("")
        w("| CVE ID | CVSS v3 | EPSS 점수 | EPSS 백분위 | 상태 |")
        w("|---|---|---|---|---|")
        for cve_id, cve in sorted(cve_cache.items()):
            cvss = cve.get("cvss") or {}
            v3 = cvss.get("v3") or {}
            epss = cve.get("epss") or {}
            score = v3.get("score", "-")
            sev = v3.get("severity", "-")
            epss_score = epss.get("score", "-")
            epss_pct = epss.get("percentile", "-")
            status = cve.get("status", "-")
            if isinstance(epss_score, float):
                epss_score = f"{epss_score:.4f}"
            if isinstance(epss_pct, float):
                epss_pct = f"{epss_pct:.2f}"
            w(f"| {cve_id} | {score} ({sev}) | {epss_score} | {epss_pct} | {status} |")
        w("")

    # ── Recommendations ──
    w("## 7. 🛡️ 권장 조치")
    w("")
    w("### 즉시 조치 (영향 확인 시)")
    w("1. 감염 패키지가 발견된 프로젝트의 `package-lock.json` / `yarn.lock` 확인")
    w("2. 3/19~23 사이 빌드 이력이 있으면 **모든 시크릿/토큰 즉시 교체**")
    w("   - npm 토큰, GitHub PAT, 클라우드 자격증명, SSH 키, Docker 자격증명")
    w("3. 빌드 서버에서 백도어 확인: `systemctl --user status pgmon`")
    w("4. C2 통신 확인: `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io` 접속 이력")
    w("")
    w("### 예방 조치")
    w("1. GitHub Actions에서 mutable tag 대신 **SHA 고정(pin)** 사용")
    w("2. npm lockfile(`package-lock.json`) 커밋 필수화")
    w("3. CI/CD 파이프라인에 SCA 스캔 상시 적용")
    w("4. XEIZE 취약점 모니터링 알림 설정")
    w("")
    w("### IOC 확인 명령어")
    w("```bash")
    w("# 파일 시스템 백도어")
    w("ls -la ~/.local/share/pgmon/service.py")
    w("ls -la ~/.config/systemd/user/pgmon.service")
    w("ls -la /tmp/pglog /tmp/.pg_state")
    w("")
    w("# C2 네트워크 통신")
    w('grep -r "icp0.io" /var/log/ 2>/dev/null')
    w('grep -r "tdtqy-oyaaa" /var/log/ 2>/dev/null')
    w("```")
    w("")
    w("---")
    w(f"*이 보고서는 XEIZE Open API v1 데이터 기반으로 자동 생성되었습니다.*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    report = run_analysis()
    # Also print summary to console
    print("\n" + "=" * 70)
    print("  DONE — Report: internal/reports/axios/canisterworm-impact-report.md")
    print("=" * 70)
