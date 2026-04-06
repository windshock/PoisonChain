#!/usr/bin/env python3
"""
Fetch recent committers for axios-using repos from Bitbucket.
Enriches bitbucket-full-scan-result.json with maintainer info.
"""

import json
import os
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bitbucket_workspace import strip_personal_from_scan
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict

ROOT_DIR = Path(__file__).resolve().parent.parent
INTERNAL_REPORTS_DIR = ROOT_DIR / "internal" / "reports"
REPORTS_DATA_DIR = INTERNAL_REPORTS_DIR / "data"
AXIOS_REPORTS_DIR = INTERNAL_REPORTS_DIR / "axios"
SCAN_JSON_PATH = REPORTS_DATA_DIR / "bitbucket-full-scan-result.json"
SCAN_MD_PATH = AXIOS_REPORTS_DIR / "bitbucket-full-scan-report.md"
MANUAL_OVERRIDES_PATH = REPORTS_DATA_DIR / "manual-overrides.json"


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
BASE_URL = os.environ.get("XEIZE_BASE_URL", "")
BB = "https://bitbucket.example.com"

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

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

def load_manual_overrides() -> dict:
    if os.path.exists(MANUAL_OVERRIDES_PATH):
        with open(MANUAL_OVERRIDES_PATH, encoding="utf-8") as f:
            return json.load(f)
    return {}

def apply_committer_patches(committers: list, patches: dict) -> list:
    """manual-overrides.json의 committer_patches를 이메일 기준으로 적용한다."""
    out = []
    for c in committers:
        patch = patches.get(c.get("email", ""))
        out.append({**c, **patch} if patch else c)
    return out

def merge_hr_enrichment(old_committers, new_committers):
    """Re-fetch loses employee_status / hr_* from check_employee_status.py — restore by email."""
    skip = frozenset({"name", "email", "date"})
    by_email = {}
    for c in old_committers or []:
        em = c.get("email")
        if not em:
            continue
        extra = {k: v for k, v in c.items() if k not in skip}
        if extra:
            by_email[em] = extra
    out = []
    for c in new_committers:
        merged = dict(c)
        ex = by_email.get(c.get("email"))
        if ex:
            merged.update(ex)
        out.append(merged)
    return out


def get_recent_committers(project_key, repo_slug, limit=5):
    """Get unique recent committers from a repo."""
    url = f"{BB}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}/commits?limit=25"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {get_pat()}"})
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as r:
            data = json.loads(r.read())
    except:
        return []

    seen = set()
    committers = []
    for commit in data.get("values", []):
        author = commit.get("author", {})
        name = author.get("name", "").strip()
        email = (author.get("emailAddress") or "").strip()
        if not email or email in seen:
            continue
        seen.add(email)
        committers.append({
            "name": name,
            "email": email,
            "date": commit.get("authorTimestamp", 0),
        })
        if len(committers) >= limit:
            break
    return committers


def main():
    with open(SCAN_JSON_PATH) as f:
        scan = json.load(f)

    dropped = strip_personal_from_scan(scan)
    if dropped:
        print(f"개인 워크스페이스(~…) axios 리포 {dropped}개 제외 후 커미터 조회")

    repos = scan["axios_versions"]
    print(f"Fetching recent committers for {len(repos)} axios repos...")

    overrides = load_manual_overrides()
    committer_patches = overrides.get("committer_patches", {})
    team_overrides = overrides.get("team_overrides", {})

    results = []
    done = 0

    def fetch(repo):
        parts = repo["name"].split("/", 1)
        pk, slug = parts[0], parts[1]
        committers = get_recent_committers(pk, slug, limit=5)
        committers = merge_hr_enrichment(repo.get("committers"), committers)
        committers = apply_committer_patches(committers, committer_patches)
        return {**repo, "committers": committers}

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(fetch, r): r for r in repos}
        for future in as_completed(futures):
            done += 1
            try:
                results.append(future.result())
            except Exception as e:
                results.append({**futures[future], "committers": [], "error": str(e)})
            if done % 100 == 0:
                print(f"  [{done}/{len(repos)}]")

    print(f"  [{done}/{len(repos)}] DONE")

    # Apply team_overrides as manual_team_override field on each repo
    for r in results:
        if r["name"] in team_overrides:
            r["manual_team_override"] = team_overrides[r["name"]]
        elif "manual_team_override" in r and r["name"] not in team_overrides:
            del r["manual_team_override"]

    # Sort by repo name
    results.sort(key=lambda x: x["name"])

    # Save enriched JSON
    scan["axios_versions"] = results
    REPORTS_DATA_DIR.mkdir(parents=True, exist_ok=True)
    AXIOS_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    with open(SCAN_JSON_PATH, "w") as f:
        json.dump(scan, f, indent=2, ensure_ascii=False)

    # Generate enhanced markdown
    md = generate_report(scan, results)
    with open(SCAN_MD_PATH, "w") as f:
        f.write(md)

    print(f"\n✅ Updated reports with committer info")

    # Stats
    total_committers = set()
    for r in results:
        for c in r.get("committers", []):
            total_committers.add(c["email"])
    print(f"   Unique committers across axios repos: {len(total_committers)}")


def generate_report(scan, results):
    lines = []
    w = lines.append

    w("# Bitbucket 전체 리포지토리 axios 공급망 공격 스캔 결과")
    w("")
    w(f"> **스캔 시각:** {scan['scan_time']}")
    w(f"> **대상:** Bitbucket 전체 {scan['total_repos']}개 리포지토리")
    w(f"> **담당자 조회:** 최근 커밋 기준 상위 5명")
    w("")
    w("## 스캔 요약")
    w("")
    w("| 항목 | 수치 |")
    w("|---|---|")
    w(f"| 전체 리포지토리 | {scan['total_repos']}개 |")
    w(f"| lockfile 보유 | {scan['with_lockfile']}개 |")
    w(f"| axios 사용 | {scan['using_axios']}개 |")
    w(f"| 🚨 감염/위험 발견 | **{scan['findings_count']}개** |")
    sr = scan.get("semver_range_risk_count", 0)
    w(f"| ⚠️ package.json 범위가 악성 패치 포함 가능 | **{sr}개** |")
    w("")

    risk_repos = [r for r in results if r.get("axios_semver_can_resolve_bad")]
    if risk_repos:
        w("## ⚠️ package.json semver (lock과 악성 불일치 가능)")
        w("")
        w("lock은 당시 resolve만 고정한다. `^1.14.0` 등은 이후 **npm install**/CI에서 악성 패치로 올라갈 수 있다.")
        w("")
        w("| 리포지토리 | lock axios | package.json | 악성 포함 가능 범위 |")
        w("|---|---|---|---|")
        for r in sorted(risk_repos, key=lambda x: x["name"]):
            spec = r.get("axios_package_json_spec", "?")
            bad = ", ".join(r["axios_semver_can_resolve_bad"])
            w(f"| {r['name']} | {r.get('version','?')} | `{spec}` | {bad} |")
        w("")

    if scan["findings_count"] == 0:
        w("## ✅ lockfile·직접 고정 악성 없음")
        w("")
        w("axios 악성 버전·plain-crypto-js·CanisterWorm 패키지가 lock에 직접 잡히지 않았다. semver 행은 별도.")
        w("")

    # Version summary
    ver_count = defaultdict(int)
    for r in results:
        ver_count[r.get("version") or "unknown"] += 1

    w("## axios 버전 분포")
    w("")
    w("| 버전 | 리포 수 | 안전여부 |")
    w("|---|---|---|")
    for v in sorted(ver_count.keys(), key=lambda x: x, reverse=True):
        safe = "🚨 **악성**" if v in {"1.14.1", "0.30.4"} else "✅"
        w(f"| {v} | {ver_count[v]}개 | {safe} |")
    w("")

    # Full repo list with committers
    w("## axios 사용 리포지토리 목록 및 담당자")
    w("")
    w("| # | 리포지토리 | axios(lock) | package.json | semver 위험 | lockfile | HR 부서(있으면) | 최근 커밋 담당자 |")
    w("|---|---|---|---|---|---|---|---|")
    for i, r in enumerate(results, 1):
        committers_str = ""
        dept_parts = []
        for c in r.get("committers", []):
            committers_str += f"{c['name']} &lt;{c['email']}&gt;, "
            pd = (c.get("hr_dept") or "").strip()
            if pd and pd not in dept_parts:
                dept_parts.append(pd)
        committers_str = committers_str.rstrip(", ") or "N/A"
        pj = r.get("axios_package_json_spec") or "—"
        risk = ", ".join(r["axios_semver_can_resolve_bad"]) if r.get("axios_semver_can_resolve_bad") else "—"
        dept_cell = ", ".join(dept_parts) if dept_parts else "—"
        w(f"| {i} | {r['name']} | {r.get('version','?')} | `{pj}` | {risk} | {r['lockfile']} | {dept_cell} | {committers_str} |")
    w("")
    w("---")
    w("*Bitbucket REST API 기반 전수 스캔 + 최근 커밋 담당자 조회 결과*")

    return "\n".join(lines)


if __name__ == "__main__":
    main()
