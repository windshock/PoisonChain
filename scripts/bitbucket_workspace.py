"""Bitbucket 저장소 이름: 조직 프로젝트 vs 개인 워크스페이스(~사번/…)."""


def is_personal_workspace_repo(repo_name: str) -> bool:
    """개인 저장소는 project key가 ~ 로 시작한다 (예: ~1004594/vue2-webpack4-template)."""
    return bool(repo_name) and repo_name.startswith("~")


def strip_personal_from_scan(scan: dict) -> int:
    """scan['axios_versions']에서 개인 워크스페이스 제거. using_axios·semver·findings 요약 갱신."""
    av = scan.get("axios_versions") or []
    n0 = len(av)
    kept = [r for r in av if not is_personal_workspace_repo(r.get("name", ""))]
    scan["axios_versions"] = kept
    removed = n0 - len(kept)
    if removed:
        scan["using_axios"] = len(kept)
        scan["semver_range_risk_count"] = sum(
            1 for r in kept if r.get("axios_semver_can_resolve_bad")
        )
        if scan.get("findings"):
            findings = scan["findings"]

            def _fname(x):
                if isinstance(x, dict):
                    return x.get("name", "")
                return str(x)

            scan["findings"] = [x for x in findings if not is_personal_workspace_repo(_fname(x))]
            scan["findings_count"] = len(scan["findings"])
    return removed
