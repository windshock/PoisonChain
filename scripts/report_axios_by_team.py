#!/usr/bin/env python3
"""
axios 사용 리포를 Bitbucket 커밋 담당자 표시명 기준으로 팀별 Markdown에 묶는다.
표시명이 `이름/팀/SKP` 또는 `이름/상위/팀/SKP`(마지막이 회사 코드)일 때 **회사 앞 토큰**을 팀으로 쓴다.

입력: internal/reports/data/bitbucket-full-scan-result.json (fetch_committers.py 이후 권장)
선택 입력: Confluence **빌드 대상 표** Markdown — 전사에서 관리하는 Jenkins 기준(기본 internal/reports/axios/axios-inventory-confluence-2026-03-31.md)
출력: internal/reports/axios/axios-repos-by-team.md
"""

import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bitbucket_workspace import is_personal_workspace_repo
from datetime import datetime

ROOT_DIR = Path(__file__).resolve().parent.parent
INTERNAL_REPORTS_DIR = ROOT_DIR / "internal" / "reports"
REPORTS_DATA_DIR = INTERNAL_REPORTS_DIR / "data"
AXIOS_REPORTS_DIR = INTERNAL_REPORTS_DIR / "axios"
DEFAULT_JSON = str(REPORTS_DATA_DIR / "bitbucket-full-scan-result.json")
OUT_MD = str(AXIOS_REPORTS_DIR / "axios-repos-by-team.md")
DEFAULT_MORNING_INVENTORY = str(AXIOS_REPORTS_DIR / "axios-inventory-confluence-2026-03-31.md")
JENKINS_SCAN_JSON = str(REPORTS_DATA_DIR / "jenkins-scan-result.json")

# Bitbucket 표시명 마지막 구간이 회사일 때 바로 앞 구간을 실제 팀으로 본다.
_DISPLAY_COMPANY_TAIL = frozenset({"SKP", "SK.COM", "SK-INC.COM", "SKINC.COM"})


def project_key_from_repo(repo_name: str) -> str:
    """Bitbucket `PROJECT/slug` 의 프로젝트 키. 팀이 아니라 표에서 참고용."""
    name = (repo_name or "").strip()
    if "/" in name:
        return name.split("/", 1)[0]
    return name or "—"


def _norm_company_token(s: str) -> str:
    return (s or "").strip().upper().replace(" ", "")


def team_from_display_name(name: str) -> str:
    """
    Bitbucket 표시명에서 **조직 팀** 추출.
    - `이름/실팀/SKP` → 실팀
    - `이름/AI/Mobility개발팀/SKP` → SKP 앞 **Mobility개발팀**(가운데 `AI`는 상위 구분만 할 때 무시)
    """
    if not name or not str(name).strip():
        return "미분류"
    parts = [p.strip() for p in str(name).split("/") if p.strip()]
    if not parts:
        return "미분류"
    last = _norm_company_token(parts[-1])
    if len(parts) >= 3 and last in _DISPLAY_COMPANY_TAIL:
        team = parts[-2] or ""
        return team.strip() if team.strip() else "미분류"
    if len(parts) >= 3:
        return parts[1] or "미분류"
    if len(parts) == 2:
        if _norm_company_token(parts[-1]) in _DISPLAY_COMPANY_TAIL:
            return "미분류"
        return parts[1] or parts[0] or "미분류"
    return "미분류"


def team_label_from_committer(c: dict) -> str:
    """조직 **팀**만: HR 부서(유효값) → Bitbucket 표시명에서 팀. (Bitbucket 프로젝트 키는 팀이 아님.)"""
    d = (c.get("hr_dept") or "").strip()
    if d and "@" not in d:
        return d
    return team_from_display_name(c.get("name", ""))


def sort_team_keys(by_team: Dict[str, List]) -> List[str]:
    """요약 표·본문 섹션 순서: 미분류를 맨 위, 나머지는 리포 수(중복) 내림차순."""
    return sorted(by_team.keys(), key=lambda t: (t != "미분류", -len(by_team[t]), t))


def resolve_mobility_vs_ai_dev_team(teams: set) -> set:
    """
    한 리포에 커밋자 표시명이 `…/AI개발팀/SKP`(옛·로컬 계정)와 `…/AI/Mobility개발팀/SKP`처럼
    섞이면 **Mobility개발팀**만 남긴다(동일 인력의 상·하위 표기 불일치 정리).
    """
    t = set(teams)
    if "Mobility개발팀" in t and "AI개발팀" in t:
        t.discard("AI개발팀")
    return t


def _unescape_md_table_cell(s: str) -> str:
    """Confluence/Word 변환 표에서 `\\_`, `**굵게**` 등 제거."""
    t = (s or "").strip().replace("\\_", "_")
    while True:
        n = re.sub(r"\*\*(.+?)\*\*", r"\1", t)
        if n == t:
            break
        t = n.strip()
    return t.strip()


def norm_repo_slug_for_match(s: str) -> str:
    """Confluence 표 레포명과 Bitbucket slug 불일치(`_` vs `-`) 완화."""
    t = _unescape_md_table_cell(s).lower()
    return t.replace("_", "-")


def load_morning_inventory_keys(md_path: str) -> set:
    """
    Confluence에 붙은 표(프로젝트 | 레포 | …)에서 (프로젝트키 대문자, 정규화 slug) 집합.
    표는 전사에서 관리하는 Jenkins 기준 빌드 대상 목록을 옮긴 것으로 가정한다.
    빈 프로젝트 열은 직전 행 프로젝트를 이어받는다.
    """
    if not md_path or not os.path.exists(md_path):
        return set()
    with open(md_path, encoding="utf-8") as f:
        text = f.read()
    keys: set = set()
    in_table = False
    current_project = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("|"):
            if line.startswith("#"):
                in_table = False
                current_project = ""
            continue
        parts = [p.strip() for p in line.split("|")]
        cells = parts[1:-1] if len(parts) > 2 else []
        if not cells:
            continue
        if "프로젝트" in cells[0]:
            in_table = True
            current_project = ""
            continue
        if not in_table:
            continue
        if cells[0].startswith(":") or "---" in line:
            continue
        proj_cell = _unescape_md_table_cell(cells[0])
        repo_cell = _unescape_md_table_cell(cells[1]) if len(cells) > 1 else ""
        if not repo_cell:
            continue
        if proj_cell:
            current_project = proj_cell
        elif not current_project:
            continue
        else:
            proj_cell = current_project
        keys.add((proj_cell.upper(), norm_repo_slug_for_match(repo_cell)))
    return keys


def scan_repo_in_morning_inventory(
    repo_full_name: str, morning_keys: set
) -> bool:
    """`PROJECT/slug` 가 Confluence 표의 프로젝트+레포와 일치하는지."""
    name = (repo_full_name or "").strip()
    if "/" not in name or not morning_keys:
        return False
    pk, slug = name.split("/", 1)
    key = (pk.strip().upper(), norm_repo_slug_for_match(slug))
    return key in morning_keys


def dominant_org_team_per_project(repos: List[dict]) -> Dict[str, Optional[str]]:
    """
    같은 Bitbucket 프로젝트(PROJECT/slug의 PROJECT) 안 axios 리포 전체 커밋자 중,
    **미분류가 아닌 팀** 출현 빈도가 가장 많은 값을 '프로젝트 대표 팀'으로 쓴다.
    (사번-only·HR 부서 없음인 담당자는 이 팀으로 묶어 상위 그룹과 맞춘다.)
    """
    by_pk: dict = defaultdict(list)
    for r in repos:
        by_pk[project_key_from_repo(r.get("name", ""))].append(r)
    out: Dict[str, Optional[str]] = {}
    for pk, plist in by_pk.items():
        cnt: Counter[str] = Counter()
        for repo in plist:
            for c in repo.get("committers") or []:
                t = team_label_from_committer(c)
                if t != "미분류":
                    cnt[t] += 1
        out[pk] = cnt.most_common(1)[0][0] if cnt else None
    return out


def load_jenkins_risk_index(path: str = JENKINS_SCAN_JSON) -> Dict[str, str]:
    """
    Loads internal/reports/data/jenkins-scan-result.json if present.
    Returns {bitbucket_repo_name: highest_risk_level} for matched repos.
    """
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    _RISK_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    index: Dict[str, str] = {}
    for result in data.get("results", []):
        repo = result.get("bitbucket_repo")
        risk = result.get("risk_level", "LOW")
        if not repo:
            continue
        current = index.get(repo)
        if current is None or _RISK_ORDER.get(risk, 0) > _RISK_ORDER.get(current, 0):
            index[repo] = risk
    return index


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_JSON
    inv_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_MORNING_INVENTORY
    if not os.path.exists(path):
        sys.exit(f"Missing {path}")

    morning_keys = load_morning_inventory_keys(inv_path)
    jenkins_risk = load_jenkins_risk_index()

    with open(path) as f:
        scan = json.load(f)

    repos = [
        r
        for r in (scan.get("axios_versions") or [])
        if not is_personal_workspace_repo(r.get("name", ""))
    ]
    project_team = dominant_org_team_per_project(repos)
    by_team = defaultdict(list)

    for repo in repos:
        pk = project_key_from_repo(repo.get("name", ""))
        inherit = project_team.get(pk)

        # manual_team_override가 있으면 무조건 그 팀으로만 분류
        manual = repo.get("manual_team_override")
        if manual:
            by_team[manual].append(repo)
            continue

        teams = set()
        for c in repo.get("committers") or []:
            t = team_label_from_committer(c)
            if t == "미분류" and inherit:
                t = inherit
            teams.add(t)
        if not teams:
            teams.add(inherit or "미분류")
        teams = resolve_mobility_vs_ai_dev_team(teams)
        for t in teams:
            by_team[t].append(repo)

    lines = []
    w = lines.append
    display_path = os.path.relpath(path, ROOT_DIR)
    display_inv_path = os.path.relpath(inv_path, ROOT_DIR) if inv_path else inv_path
    w("# axios 사용 리포지토리 — 팀별 그룹")
    w("")
    w(
        "> **범위:** Bitbucket **개인 워크스페이스** (`~100xxxx/reponame` 형태) 리포는 조직 스캔에서 제외한다."
    )
    w("")
    w(f"> **생성 시각:** {datetime.now().isoformat(timespec='seconds')}")
    w(f"> **원본:** `{display_path}`")
    w("")
    w(
        "> **「전사 Jenkins 목록」열:** Confluence에 올라온 표 — **회사에서 운영하는 Jenkins**에 묶여 "
        "빌드·배포되는 **프로젝트·리포 목록**과, 이 보고의 Bitbucket 리포 이름(`프로젝트/슬러그`)을 맞춘 것이다. "
        "**○**는 그 **목록 표에 이 리포가 있다**는 뜻이고, **—**는 없다."
    )
    w("")
    w(
        "> **여기에 안 잡히는 것(각 팀에서 직접 확인):** **팀·개인 개발 PC**에서만 돌리는 빌드, "
        "**팀만의 Jenkins**·**사업부 Jenkins**에서만 돌리는 빌드는 **위 회사 Jenkins 목록 표에 안 올라올 수 있다**. "
        "○/—와 관계없이 **팀 Jenkins·로컬 빌드**까지는 **각 팀이 따로 점검**해야 한다."
    )
    w("")
    if morning_keys:
        w(
            f"> **매칭 소스:** `{display_inv_path}` — 표 기준 **{len(morning_keys)}**건의 `프로젝트/레포`와 짝을 맞춤. "
            "일치 시 열에 **○**, 아니면 **—**."
        )
    else:
        w(
            f"> **매칭 소스:** 없음 또는 파싱 0건 (`{display_inv_path}`). 열은 전부 **—**."
        )
    w("")
    w(
        "**팀(조직):** 커밋자별로 `hr_dept` → Bitbucket 표시명: 마지막이 **SKP** 등이면 "
        "**바로 앞 토큰**이 팀(`…/AI/Mobility개발팀/SKP` → Mobility개발팀). "
        "한 리포에 **AI개발팀**과 **Mobility개발팀**이 같이 나오면 Mobility만 쓴다(표시명 이중 등록 정리). "
        "**미분류**는 프로젝트 단위 다수결 팀을 물려 쓴 뒤에도 남는 경우. **Bitbucket 프로젝트** 열은 참고."
    )
    w("")
    if jenkins_risk:
        w(
            f"> **Jenkins 위험도:** `{JENKINS_SCAN_JSON}` 기준 — Jenkins 빌드 잡과 매칭된 리포의 최고 위험도. "
            "CRITICAL/HIGH/MEDIUM/LOW 순."
        )
        w("")
    w("| 팀 | 리포 수(중복 허용) |")
    w("|---|---|")
    for t in sort_team_keys(by_team):
        w(f"| {t} | {len(by_team[t])}개 |")
    w("")
    w("동일 리포가 여러 팀에 잡힐 수 있다(담당 커밋자가 서로 다른 팀일 때).")
    w("")

    jenkins_header = " Jenkins 위험도 |" if jenkins_risk else ""
    jenkins_sep = "---|" if jenkins_risk else ""

    for t in sort_team_keys(by_team):
        w(f"## {t}")
        w("")
        w(
            f"| 리포지토리 | 전사 Jenkins 목록 | Bitbucket 프로젝트 | axios(lock) | package.json | semver 위험 |{jenkins_header} 담당자 |"
        )
        w(f"|---|---|---|---|---|---|{jenkins_sep}---|")
        for r in sorted(by_team[t], key=lambda x: x["name"]):
            bbp = project_key_from_repo(r.get("name", ""))
            morning_cell = (
                "○"
                if scan_repo_in_morning_inventory(r.get("name", ""), morning_keys)
                else "—"
            )
            pj = r.get("axios_package_json_spec") or "—"
            risk = (
                ", ".join(r["axios_semver_can_resolve_bad"])
                if r.get("axios_semver_can_resolve_bad")
                else "—"
            )
            cells = []
            for c in r.get("committers") or []:
                nm = c.get("name", "")
                em = c.get("email", "")
                st = c.get("employee_status", "")
                pd = (c.get("hr_dept") or "").strip()
                suf = f" ({st})" if st else ""
                if pd:
                    suf += f" [hr_portal: {pd}]"
                cells.append(f"{nm} &lt;{em}&gt;{suf}")
            jenkins_cell = ""
            if jenkins_risk:
                jrisk = jenkins_risk.get(r.get("name", ""), "—")
                jenkins_cell = f" {jrisk} |"
            w(
                f"| {r['name']} | {morning_cell} | `{bbp}` | {r.get('version', '?')} | `{pj}` | {risk} |{jenkins_cell}"
                f" {', '.join(cells) or '—'} |"
            )
        w("")

    AXIOS_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_MD, "w") as f:
        f.write("\n".join(lines))
    print(f"✅ Wrote {OUT_MD} ({len(by_team)} teams, {len(repos)} repos)")


if __name__ == "__main__":
    main()
