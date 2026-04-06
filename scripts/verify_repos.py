#!/usr/bin/env python3
"""
Bitbucket 리포 존재 여부 확인 및 스캔 결과 정리.

역할:
  1. internal/reports/data/manual-overrides.json 의 excluded_repos 를 스캔 결과에서 제거
  2. 남은 axios 리포를 Bitbucket API 로 실제 존재 여부 확인
  3. 404(삭제된) 리포를 제거하고 internal/reports/data/bitbucket-full-scan-result.json 갱신
  4. internal/reports/axios/bitbucket-full-scan-report.md 재생성 (fetch_committers.py 재호출)

사용법:
  python3 scripts/verify_repos.py [--dry-run]

  --dry-run  실제 삭제 없이 결과만 출력
"""

import json
import os
import ssl
import sys
import urllib.request
import urllib.error
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

ROOT_DIR = Path(__file__).resolve().parent.parent
REPORTS_DATA_DIR = ROOT_DIR / "internal" / "reports" / "data"

SCAN_JSON      = str(REPORTS_DATA_DIR / "bitbucket-full-scan-result.json")
OVERRIDES_PATH = str(REPORTS_DATA_DIR / "manual-overrides.json")
BB             = "https://bitbucket.example.com"

# ---------------------------------------------------------------------------
# Env / auth
# ---------------------------------------------------------------------------

def load_env(path=ROOT_DIR / ".env"):
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())

load_env()

API_KEY  = os.environ.get("XEIZE_API_KEY", "")
BASE_URL = os.environ.get("XEIZE_BASE_URL", "https://xeize.example/open-api/v1").rstrip("/")

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE

_PAT = None

def get_pat() -> str:
    global _PAT
    if _PAT:
        return _PAT
    req = urllib.request.Request(
        f"{BASE_URL}/projects",
        headers={"Authorization": f"Bearer {API_KEY}"},
    )
    with urllib.request.urlopen(req, context=SSL_CTX) as r:
        projects = json.loads(r.read())
    for p in projects:
        if p.get("integrationId"):
            try:
                req2 = urllib.request.Request(
                    f"{BASE_URL}/git/credentials?project_id={p['id']}",
                    headers={"Authorization": f"Bearer {API_KEY}"},
                )
                with urllib.request.urlopen(req2, context=SSL_CTX) as r2:
                    creds = json.loads(r2.read())
                    _PAT = creds.get("personalAccessToken")
                    if _PAT:
                        return _PAT
            except Exception:
                pass
    sys.exit("ERROR: Bitbucket PAT 취득 실패")


def repo_exists(project_key: str, repo_slug: str) -> bool:
    url = f"{BB}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {get_pat()}"})
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=10):
            return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    dry_run = "--dry-run" in sys.argv

    if not os.path.exists(SCAN_JSON):
        sys.exit(f"ERROR: {SCAN_JSON} 없음")

    with open(SCAN_JSON, encoding="utf-8") as f:
        scan = json.load(f)

    # 1. excluded_repos 적용
    overrides    = {}
    excluded_set = set()
    if os.path.exists(OVERRIDES_PATH):
        with open(OVERRIDES_PATH, encoding="utf-8") as f:
            overrides = json.load(f)
        excluded_set = set(overrides.get("excluded_repos", []))

    repos = scan.get("axios_versions", [])
    before_count = len(repos)

    excluded_removed = [r for r in repos if r["name"] in excluded_set]
    repos = [r for r in repos if r["name"] not in excluded_set]
    if excluded_removed:
        print(f"📋 excluded_repos 제거: {len(excluded_removed)}개")
        for r in excluded_removed:
            print(f"   - {r['name']}")

    # 2. Bitbucket API 존재 확인 (병렬)
    print(f"\n🔍 Bitbucket 리포 존재 확인 중 ({len(repos)}개)...")

    results = {}

    def check(repo):
        name = repo["name"]
        pk, slug = name.split("/", 1)
        return name, repo_exists(pk, slug)

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(check, r): r for r in repos}
        done = 0
        for future in as_completed(futures):
            done += 1
            name, exists = future.result()
            results[name] = exists
            if done % 50 == 0:
                print(f"  [{done}/{len(repos)}]")
    print(f"  [{len(repos)}/{len(repos)}] DONE")

    deleted = [name for name, exists in results.items() if not exists]
    alive   = [r for r in repos if results.get(r["name"], True)]

    print(f"\n결과:")
    print(f"  ✅ 존재:  {len(alive)}개")
    print(f"  🗑️  삭제됨: {len(deleted)}개")
    if deleted:
        for name in sorted(deleted):
            print(f"     - {name}")

    if dry_run:
        print("\n[dry-run] 변경 없이 종료.")
        return

    # 3. 삭제된 리포 제거 후 JSON 저장
    removed_total = before_count - len(alive)
    if removed_total == 0:
        print("\n변경 없음 — JSON 그대로 유지.")
        return

    scan["axios_versions"] = alive
    scan["using_axios"]    = len(alive)
    # semver_range_risk_count 재계산
    scan["semver_range_risk_count"] = sum(
        1 for r in alive if r.get("axios_semver_can_resolve_bad")
    )

    with open(SCAN_JSON, "w", encoding="utf-8") as f:
        json.dump(scan, f, ensure_ascii=False, indent=2)
    print(f"\n✅ {SCAN_JSON} 저장 완료 (제거 {removed_total}개 → {len(alive)}개 남음)")

    # 4. 하위 리포트 재생성
    print("\n==> fetch_committers.py 재실행 (MD 재생성)...")
    subprocess.run([sys.executable, "scripts/fetch_committers.py"], check=True)
    print("==> report_axios_by_team.py 재실행...")
    subprocess.run([sys.executable, "scripts/report_axios_by_team.py"], check=True)
    print("\n✅ 리포트 재생성 완료.")


if __name__ == "__main__":
    main()
