#!/usr/bin/env python3
"""
CanisterWorm 공급망 공격 대응 — Jenkins 인스턴스 스캔.

각 Jenkins 인스턴스에서 빌드 잡을 수집하고, config.xml의 SCM URL을
reports/bitbucket-full-scan-result.json의 axios semver 위험 리포와 매칭하여
공격 윈도우 내 빌드 여부·npm 패턴을 기반으로 위험도를 산정한다.

사용법:
  python3 scripts/jenkins_scan.py [--instance-url URL] [--dry-run] [--lab]

  --instance-url URL  해당 URL 하나만 스캔 (테스트용)
  --dry-run           실제 요청 없이 스캔 대상만 출력
  --lab               http://localhost:18080 을 admin:admin123 으로 스캔 (로컬 테스트용)

출력: reports/jenkins-scan-result.json
"""

import json
import os
import re
import sys
import urllib.request
import urllib.error
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ATTACK_START = 1774916460000  # 2026-03-31 00:21 UTC (ms)
ATTACK_END   = 1774928400000  # 2026-03-31 03:40 UTC (ms)

INSTANCES_JSON = "config/jenkins-instances.json"
BITBUCKET_JSON = "reports/bitbucket-full-scan-result.json"
OUTPUT_JSON    = "reports/jenkins-scan-result.json"

REQUEST_TIMEOUT = 10  # seconds per HTTP call

# ---------------------------------------------------------------------------
# Env
# ---------------------------------------------------------------------------

def load_env(path: str = ".env") -> None:
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())


load_env()

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _basic_auth_header(user: str, token: str) -> str:
    return "Basic " + b64encode(f"{user}:{token}".encode()).decode()


def http_get(url: str, auth_header: str | None = None, timeout: int = REQUEST_TIMEOUT) -> bytes:
    """Simple GET; raises urllib.error.URLError / HTTPError on failure."""
    req = urllib.request.Request(url)
    if auth_header:
        req.add_header("Authorization", auth_header)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def try_get(url: str, auth_header: str | None = None) -> bytes | None:
    """GET with silent error handling; returns None on any error."""
    try:
        return http_get(url, auth_header)
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Auth strategy
# ---------------------------------------------------------------------------

def resolve_auth(instance_id: int, lab: bool = False) -> str | None:
    """
    Returns an Authorization header string, or None for anonymous.
    Priority: JENKINS_TOKEN_{id} → JENKINS_TOKEN (단일 인스턴스용) → lab admin fallback → None.
    """
    token = (
        os.environ.get(f"JENKINS_TOKEN_{instance_id}", "").strip()
        or os.environ.get("JENKINS_TOKEN", "").strip()
    )
    if token:
        if ":" in token:
            user, pw = token.split(":", 1)
        else:
            user, pw = "jenkins", token
        return _basic_auth_header(user, pw)
    if lab:
        return _basic_auth_header("admin", "admin123")
    return None

# ---------------------------------------------------------------------------
# Jenkins API
# ---------------------------------------------------------------------------

def _fetch_jobs_at(url: str, auth: str | None) -> list[dict] | None:
    """GET jobs list at a specific Jenkins URL (root or folder). Returns None on failure."""
    query = url.rstrip("/") + "/api/json?tree=jobs[name,url,_class,lastBuild[timestamp,result],lastSuccessfulBuild[timestamp],jobs[name,lastBuild[timestamp,result]]]"
    try:
        raw = http_get(query)
        return json.loads(raw).get("jobs", [])
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403):
            return None
    except Exception:
        return None
    if auth is None:
        return None
    try:
        raw = http_get(query, auth_header=auth)
        return json.loads(raw).get("jobs", [])
    except Exception:
        return None


def fetch_jobs(base_url: str, auth: str | None) -> list[dict] | None:
    """
    재귀적으로 폴더를 탐색해 전체 잡 목록 반환.
    Folder 클래스는 펼쳐서 하위 잡을 모두 수집한다.
    """
    top = _fetch_jobs_at(base_url, auth)
    if top is None:
        return None

    result: list[dict] = []
    queue = list(top)
    visited: set[str] = set()

    while queue:
        job = queue.pop(0)
        job_class = job.get("_class", "")
        job_url = job.get("url", "")

        # Folder 계열: 하위 잡을 재귀 탐색
        if "Folder" in job_class or "OrganizationFolder" in job_class:
            if job_url and job_url not in visited:
                visited.add(job_url)
                children = _fetch_jobs_at(job_url, auth)
                if children:
                    queue.extend(children)
            continue  # 폴더 자체는 결과에 포함하지 않음

        result.append(job)

    return result


def fetch_config_xml(base_url: str, job_name: str, auth: str | None, job_url: str | None = None) -> str | None:
    """config.xml always requires auth; falls back to lab admin:admin123."""
    # job_url이 있으면 그걸 사용 (폴더 중첩 경로 대응)
    if job_url:
        url = job_url.rstrip("/") + "/config.xml"
    else:
        url = base_url.rstrip("/") + f"/job/{urllib.parse.quote(job_name, safe='')}/config.xml"
    if auth is not None:
        raw = try_get(url, auth_header=auth)
        if raw is not None:
            return raw.decode("utf-8", errors="replace")
    # Try without auth as last resort
    raw = try_get(url)
    return raw.decode("utf-8", errors="replace") if raw else None


def fetch_recent_builds(base_url: str, job_name: str, auth: str | None, job_url: str | None = None) -> list[dict]:
    """GET /job/{name}/api/json?tree=builds[timestamp,result]{0,200}

    200개로 설정하는 이유: CI/CD 잡은 하루 수십 회 빌드하므로 20개면 공격 기간
    (2026-03-31 00:21~03:40 UTC)이 최근 빌드에 묻혀 누락될 수 있음.
    200개면 하루 6회 빌드 기준 33일치 커버 → 공격 기간 누락 방지.
    """
    if job_url:
        url = job_url.rstrip("/") + "/api/json?tree=builds[timestamp,result]{0,200}"
    else:
        url = (
            base_url.rstrip("/")
            + f"/job/{urllib.parse.quote(job_name, safe='')}/api/json"
            + "?tree=builds[timestamp,result]{0,200}"
        )
    raw = try_get(url, auth_header=auth)
    if raw is None:
        return []
    try:
        return json.loads(raw).get("builds", [])
    except Exception:
        return []


# urllib.parse needed for quote
import urllib.parse

# ---------------------------------------------------------------------------
# Config.xml parsing
# ---------------------------------------------------------------------------

_SCM_URL_RE = re.compile(r"<url>\s*(https?://[^\s<]+\.git[^<]*?)\s*</url>", re.IGNORECASE)
_SCM_REMOTE_RE = re.compile(r"<remote>\s*(https?://[^\s<]+)\s*</remote>", re.IGNORECASE)
_BITBUCKET_SCM_RE = re.compile(
    r"https?://[^/]*bitbucket[^/]*/scm/([A-Z0-9_\-]+)/([a-zA-Z0-9_.\-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


def parse_config_xml(xml_text: str) -> dict:
    """
    Returns:
      scm_url: str | None
      bitbucket_repo: str | None   — "PROJECT/slug" normalised
      uses_npm_install: bool | None  — None when job is Pipeline-from-SCM or Multibranch
      uses_npm_ci: bool | None       — None when job is Pipeline-from-SCM or Multibranch
      is_pipeline_scm: bool          — CpsScmFlowDefinition detected
      is_multibranch: bool           — WorkflowMultiBranchProject detected
    """
    result = {
        "scm_url": None,
        "bitbucket_repo": None,
        "uses_npm_install": False,
        "uses_npm_ci": False,
        "is_pipeline_scm": False,
        "is_multibranch": False,
    }

    # Pipeline type detection
    if "CpsScmFlowDefinition" in xml_text:
        result["is_pipeline_scm"] = True
    if "WorkflowMultiBranchProject" in xml_text:
        result["is_multibranch"] = True

    # SCM URL — try <url> first, then <remote> (GitSCMSource for Multibranch)
    m = _SCM_URL_RE.search(xml_text)
    if not m:
        # Fallback: any <url> in xml that looks like bitbucket
        m2 = re.search(r"<url>\s*(https?://[^\s<]+)\s*</url>", xml_text, re.IGNORECASE)
        if m2:
            url = m2.group(1).strip()
            if "bitbucket" in url.lower():
                result["scm_url"] = url
    else:
        result["scm_url"] = m.group(1).strip()

    # <remote> tag — GitSCMSource used by Multibranch Pipeline
    if not result["scm_url"]:
        rm = _SCM_REMOTE_RE.search(xml_text)
        if rm:
            url = rm.group(1).strip()
            if "bitbucket" in url.lower():
                result["scm_url"] = url

    if result["scm_url"]:
        bm = _BITBUCKET_SCM_RE.match(result["scm_url"])
        if bm:
            proj = bm.group(1).upper()
            slug = bm.group(2).lower().rstrip("/")
            result["bitbucket_repo"] = f"{proj}/{slug}"

    # Pipeline-from-SCM and Multibranch: npm commands live in Jenkinsfile, not config.xml
    if result["is_pipeline_scm"] or result["is_multibranch"]:
        result["uses_npm_install"] = None
        result["uses_npm_ci"] = None
        return result

    # npm patterns — search entire xml text (shell command blocks)
    text_lower = xml_text.lower()
    # npm install (exclude --ignore-scripts and -g)
    for m2 in re.finditer(r"npm\s+install", text_lower):
        ctx = text_lower[m2.start():m2.start() + 60]
        if "--ignore-scripts" not in ctx and " -g" not in ctx and " --global" not in ctx:
            result["uses_npm_install"] = True
            break
    # npm ci
    if re.search(r"npm\s+ci(?:\s|$|&)", text_lower):
        result["uses_npm_ci"] = True
    # yarn install → treat like npm install
    if re.search(r"yarn\s+install", text_lower):
        result["uses_npm_install"] = True

    return result

# ---------------------------------------------------------------------------
# Bitbucket repo index
# ---------------------------------------------------------------------------

def load_bitbucket_index(path: str = BITBUCKET_JSON) -> dict[str, dict]:
    """Returns {normalized_name: repo_dict} for all repos in the scan."""
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    index: dict[str, dict] = {}
    for repo in data.get("axios_versions", []):
        name = repo.get("name", "")
        # Normalize: uppercase project, lowercase slug, replace _ with - in slug
        if "/" in name:
            proj, slug = name.split("/", 1)
            key = f"{proj.upper()}/{slug.lower()}"
            index[key] = repo
    return index


def match_repo(bitbucket_repo: str | None, index: dict[str, dict]) -> dict | None:
    """Match a parsed SCM repo name against the bitbucket index."""
    if not bitbucket_repo:
        return None
    if "/" not in bitbucket_repo:
        return None
    proj, slug = bitbucket_repo.split("/", 1)
    key = f"{proj.upper()}/{slug.lower()}"
    # Exact
    if key in index:
        return index[key]
    # Slug with _ vs - normalization
    key2 = f"{proj.upper()}/{slug.lower().replace('-', '_')}"
    if key2 in index:
        return index[key2]
    key3 = f"{proj.upper()}/{slug.lower().replace('_', '-')}"
    if key3 in index:
        return index[key3]
    return None

# ---------------------------------------------------------------------------
# Risk level
# ---------------------------------------------------------------------------

def compute_risk(
    repo: dict | None,
    uses_npm_install: bool | None,
    uses_npm_ci: bool | None,
    builds: list[dict],
    last_build_ts: int | None,
) -> tuple[str, bool | None]:
    """
    Returns (risk_level, last_build_in_attack_window).
    last_build_in_attack_window is None when no build history exists.
    uses_npm_install / uses_npm_ci may be None for Pipeline-from-SCM or Multibranch
    jobs where npm commands live in a Jenkinsfile; None is treated conservatively
    as "npm install may be present".
    """
    if repo is None or not repo.get("axios_semver_can_resolve_bad"):
        return "LOW", None

    # Determine if any build fell in attack window
    in_window: bool | None = None
    after_window: bool | None = None

    if builds:
        for b in builds:
            ts = b.get("timestamp")
            if ts is None:
                continue
            if ATTACK_START <= ts <= ATTACK_END:
                in_window = True
                break
            elif ts > ATTACK_END:
                after_window = True
        if in_window is None and after_window is None and last_build_ts:
            # Use last_build_ts as fallback
            if ATTACK_START <= last_build_ts <= ATTACK_END:
                in_window = True
            elif last_build_ts > ATTACK_END:
                after_window = True

    # None means Pipeline/Multibranch — npm install may be present (conservative)
    npm_possible = uses_npm_install is True or uses_npm_install is None
    npm_ci_possible = uses_npm_ci is True or uses_npm_ci is None

    if in_window and npm_possible:
        return "CRITICAL", True
    if after_window and npm_possible:
        return "HIGH", False
    if npm_ci_possible:
        return "MEDIUM", in_window
    if npm_possible:
        return "MEDIUM", None
    return "LOW", None

# ---------------------------------------------------------------------------
# Team extraction
# ---------------------------------------------------------------------------

def extract_team(repo: dict) -> str | None:
    if not repo:
        return None
    manual = repo.get("manual_team_override")
    if manual:
        return manual
    for c in repo.get("committers") or []:
        dept = (c.get("hr_dept") or "").strip()
        if dept and "@" not in dept:
            return dept
    return None


def summarize_jobs(all_jobs: list[dict]) -> dict:
    """Build stable aggregate counts from per-job entries."""
    matched_repo_names = sorted(
        {j["bitbucket_repo"] for j in all_jobs if j.get("bitbucket_repo")}
    )
    risk_counts: dict[str, int] = {}
    for job in all_jobs:
        risk = job.get("risk_level", "LOW")
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    return {
        "matched_jobs": sum(1 for j in all_jobs if j.get("bitbucket_repo")),
        "matched_repos": len(matched_repo_names),
        "matched_repo_names": matched_repo_names,
        "risk_counts": risk_counts,
        "jobs_with_npm_install": sum(1 for j in all_jobs if j.get("uses_npm_install") is True),
        "jobs_with_npm_ci": sum(1 for j in all_jobs if j.get("uses_npm_ci") is True),
        "jobs_in_attack_window": sum(
            1 for j in all_jobs if j.get("last_build_in_attack_window") is True
        ),
        "jobs_missing_build_history": sum(
            1 for j in all_jobs if j.get("last_build_timestamp") is None
        ),
        "pipeline_jobs_without_inline_command_visibility": sum(
            1
            for j in all_jobs
            if j.get("uses_npm_install") is None or j.get("uses_npm_ci") is None
        ),
    }

# ---------------------------------------------------------------------------
# Scan a single instance
# ---------------------------------------------------------------------------

def scan_instance(instance: dict, bb_index: dict[str, dict], lab: bool = False) -> dict:
    """
    Scans one Jenkins instance. Returns a dict with:
      instance_id, instance_url, jobs (list of job result dicts),
      error (str | None), skipped (bool)
    """
    iid = instance["id"]
    base_url = instance["url"].rstrip("/")
    auth = resolve_auth(iid, lab=lab)

    result = {
        "instance_id": iid,
        "instance_url": base_url,
        "jobs": [],
        "error": None,
        "skipped": False,
    }

    jobs = fetch_jobs(base_url, auth)
    if jobs is None:
        result["error"] = f"Unreachable or auth failed: {base_url}"
        result["skipped"] = True
        return result

    for job in jobs:
        job_name = job.get("name", "")
        job_url = job.get("url") or None
        last_build = job.get("lastBuild") or {}
        last_build_ts = last_build.get("timestamp")  # ms or None

        config_xml = fetch_config_xml(base_url, job_name, auth, job_url=job_url)
        if config_xml is None:
            parsed = {"scm_url": None, "bitbucket_repo": None,
                      "uses_npm_install": False, "uses_npm_ci": False,
                      "is_pipeline_scm": False, "is_multibranch": False}
        else:
            parsed = parse_config_xml(config_xml)

        job_class = job.get("_class", "")
        is_multibranch_job = "MultiBranch" in job_class or "multibranch" in job_class.lower()

        builds = fetch_recent_builds(base_url, job_name, auth, job_url=job_url)

        # Multibranch: aggregate builds from sub-jobs (branch jobs)
        if parsed.get("is_multibranch") or is_multibranch_job:
            sub_jobs = job.get("jobs") or []
            for sub in sub_jobs:
                sub_name = sub.get("name", "")
                sub_url = sub.get("url") or None
                sub_builds = fetch_recent_builds(base_url, f"{job_name}/job/{sub_name}", auth, job_url=sub_url)
                builds.extend(sub_builds or [])
            sub_ts_list = [s.get("lastBuild", {}).get("timestamp") for s in sub_jobs if s.get("lastBuild")]
            if sub_ts_list:
                last_build_ts = max(t for t in sub_ts_list if t)

        matched_repo = match_repo(parsed["bitbucket_repo"], bb_index)
        risk, in_window = compute_risk(
            matched_repo,
            parsed["uses_npm_install"],
            parsed["uses_npm_ci"],
            builds,
            last_build_ts,
        )

        team = extract_team(matched_repo) if matched_repo else None

        entry: dict = {
            "instance_id": iid,
            "instance_url": base_url,
            "job_name": job_name,
            "bitbucket_repo": matched_repo["name"] if matched_repo else None,
            "scm_url": parsed["scm_url"],
            "uses_npm_install": parsed["uses_npm_install"],
            "uses_npm_ci": parsed["uses_npm_ci"],
            "is_pipeline_scm": parsed.get("is_pipeline_scm", False),
            "is_multibranch": parsed.get("is_multibranch", False),
            "last_build_timestamp": last_build_ts,
            "last_build_in_attack_window": in_window,
            "risk_level": risk,
            "semver_can_resolve_bad": matched_repo.get("axios_semver_can_resolve_bad") if matched_repo else None,
            "axios_spec": matched_repo.get("axios_package_json_spec") if matched_repo else None,
            "team": team,
        }
        result["jobs"].append(entry)

    return result

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    lab = "--lab" in args

    instance_url: str | None = None
    if "--instance-url" in args:
        idx = args.index("--instance-url")
        if idx + 1 < len(args):
            instance_url = args[idx + 1]

    # .env에 JENKINS_URL이 있으면 단일 인스턴스 모드로 자동 전환
    if not instance_url and not lab:
        env_url = os.environ.get("JENKINS_URL", "").strip()
        if env_url:
            instance_url = env_url

    # Load instances
    with open(INSTANCES_JSON, encoding="utf-8") as f:
        inventory_instances: list[dict] = json.load(f)["instances"]
    inventory_count = len(inventory_instances)
    instances = list(inventory_instances)
    scan_mode = "batch"

    if lab:
        instances = [{"id": 0, "url": "http://localhost:18080", "ip": "localhost", "protocol": "http", "port": 18080, "version": "lab"}]
        print("🧪 Lab 모드: http://localhost:18080 (admin:admin123)")
        scan_mode = "lab"
    elif instance_url:
        instances = [{"id": 0, "url": instance_url, "ip": "", "protocol": "http", "port": 80, "version": "unknown"}]
        print(f"🔍 단일 인스턴스: {instance_url}")
        scan_mode = "single-instance"

    if dry_run:
        print(f"[dry-run] 스캔 대상 인스턴스 {len(instances)}개:")
        for inst in instances:
            token_key = f"JENKINS_TOKEN_{inst['id']}"
            has_token = bool(os.environ.get(token_key))
            auth_note = f"token({token_key})" if has_token else ("lab admin" if lab else "anonymous")
            print(f"  [{inst['id']}] {inst['url']}  auth={auth_note}")
        return

    # Load Bitbucket index
    bb_index = load_bitbucket_index()
    print(f"📋 Bitbucket 인덱스: {len(bb_index)}개 리포")

    # Parallel scan
    all_jobs: list[dict] = []
    skipped = 0
    scanned = 0

    max_workers = min(10, len(instances))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_instance, inst, bb_index, lab): inst for inst in instances}
        for future in as_completed(futures):
            inst = futures[future]
            try:
                res = future.result()
            except Exception as exc:
                print(f"⚠️  [{inst['id']}] {inst['url']} — 예외: {exc}", file=sys.stderr)
                skipped += 1
                continue

            if res["skipped"]:
                print(f"⚠️  [{inst['id']}] {inst['url']} — 건너뜀: {res['error']}", file=sys.stderr)
                skipped += 1
            else:
                scanned += 1
                job_count = len(res["jobs"])
                matched = sum(1 for j in res["jobs"] if j["bitbucket_repo"])
                print(f"✅ [{inst['id']}] {inst['url']} — 잡 {job_count}개, 매칭 {matched}개")
                all_jobs.extend(res["jobs"])

    summary = summarize_jobs(all_jobs)
    partial_scan_reasons: list[str] = []
    if scan_mode == "lab":
        partial_scan_reasons.append("lab 모드")
    elif scan_mode == "single-instance":
        partial_scan_reasons.append("단일 인스턴스 모드")
    if scan_mode == "batch" and (scanned + skipped) < inventory_count:
        partial_scan_reasons.append("현재 결과가 전체 인벤토리보다 적은 인스턴스만 포함")
    if skipped:
        partial_scan_reasons.append("일부 대상 인스턴스가 인증 실패 또는 미접속")
    partial_scan_reasons = list(dict.fromkeys(partial_scan_reasons))
    partial_scan = bool(partial_scan_reasons)

    output = {
        "scan_time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scan_mode": scan_mode,
        "inventory_instance_count": inventory_count,
        "instances_targeted": len(instances),
        "instances_scanned": scanned,
        "instances_skipped": skipped,
        "partial_scan": partial_scan,
        "partial_scan_reasons": partial_scan_reasons,
        "total_jobs_found": len(all_jobs),
        "matched_jobs": summary["matched_jobs"],
        "matched_repos": summary["matched_repos"],
        "summary": summary,
        "results": all_jobs,
    }

    os.makedirs("reports", exist_ok=True)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\n📄 결과: {OUTPUT_JSON}")
    print(f"   인벤토리: {inventory_count}, 이번 대상: {len(instances)}")
    print(f"   인스턴스 스캔: {scanned}, 건너뜀: {skipped}")
    print(
        f"   전체 잡: {len(all_jobs)}, 매칭 잡: {summary['matched_jobs']}, "
        f"매칭된 리포: {summary['matched_repos']}"
    )
    if partial_scan_reasons:
        print("   부분 수집:", "; ".join(partial_scan_reasons))

    if summary["risk_counts"]:
        print(
            "   위험도 분포:",
            ", ".join(f"{k}:{v}" for k, v in sorted(summary["risk_counts"].items())),
        )


if __name__ == "__main__":
    main()
