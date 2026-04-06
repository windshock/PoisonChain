#!/usr/bin/env bash
# 전체 분석 파이프라인 (internal/docs/PROJECT-OVERVIEW.md §4 요약)
#
# 사용법:
#   ./scripts/run_full_pipeline.sh                 # XEIZE 분석 + Bitbucket 전수 + 커미터 + 팀 리포트
#   ./scripts/run_full_pipeline.sh --with-pnet   # 위 + 재직 조회 후 fetch_committers 재실행
#   ./scripts/run_full_pipeline.sh --pnet-refresh  # pnet만: 재직·부서 JSON 반영 + axios-repos-by-team.md만 (짧음)
#   ./scripts/run_full_pipeline.sh --with-lockfile # 위 + canisterworm_lockfile_scan (/tmp/npm_projects.json 필요)
#   ./scripts/run_full_pipeline.sh --with-jenkins  # 위 + jenkins_scan.py (Jenkins 인스턴스 스캔)
#
# 환경: 저장소 루트의 .env (XEIZE_* 등). PY=python3.12 처럼 인터프리터 덮어쓰기 가능.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY="${PY:-python3}"

WITH_PNET=0
WITH_LOCKFILE=0
PNET_REFRESH=0
WITH_JENKINS=0
for arg in "$@"; do
  case "$arg" in
    --with-pnet)     WITH_PNET=1 ;;
    --with-lockfile) WITH_LOCKFILE=1 ;;
    --with-jenkins)  WITH_JENKINS=1 ;;
    --pnet-refresh)  PNET_REFRESH=1 ;;
    -h|--help)
      grep '^#' "$0" | grep -v '^#!' | sed 's/^# //' | head -24
      exit 0
      ;;
  esac
done

if [[ ! -f .env ]]; then
  echo "WARN: .env 없음 — XEIZE·pnet 스크립트는 실패할 수 있음" >&2
fi

if [[ "$PNET_REFRESH" == "1" ]]; then
  echo "==> pnet만: check_employee_status.py (기존 bitbucket-full-scan-result.json 갱신)"
  $PY scripts/check_employee_status.py
  echo "==> pnet만: report_axios_by_team.py"
  $PY scripts/report_axios_by_team.py
  echo "완료. internal/reports/data/bitbucket-full-scan-result.json · internal/reports/axios/axios-repos-by-team.md 갱신됨."
  exit 0
fi

echo "==> [1] canisterworm_analysis.py"
$PY scripts/canisterworm_analysis.py

if [[ "$WITH_LOCKFILE" == "1" ]]; then
  echo "==> [2] canisterworm_lockfile_scan.py (/tmp/npm_projects.json 필요)"
  $PY scripts/canisterworm_lockfile_scan.py
fi

echo "==> [3] bitbucket_full_scan.py (시간 오래 걸릴 수 있음)"
$PY scripts/bitbucket_full_scan.py

echo "==> [4] verify_repos.py (삭제된 리포 정리 + excluded_repos 적용)"
$PY scripts/verify_repos.py

echo "==> [5] fetch_committers.py (1차, manual-overrides 패치 포함)"
$PY scripts/fetch_committers.py

if [[ "$WITH_PNET" == "1" ]]; then
  echo "==> [6] check_employee_status.py (PNET_COOKIE 필요)"
  if $PY scripts/check_employee_status.py; then
    echo "==> [7] fetch_committers.py (2차, pnet_dept + manual-overrides MD 반영)"
    $PY scripts/fetch_committers.py
  else
    echo "WARN: 재직 조회 실패(.env 의 PNET_COOKIE 없음·만료·망 등). 나머지는 계속." >&2
  fi
fi

echo "==> [8] report_axios_by_team.py"
$PY scripts/report_axios_by_team.py

if [[ "$WITH_JENKINS" == "1" ]]; then
  echo "==> [9] jenkins_scan.py (Jenkins 인스턴스 스캔)"
  $PY scripts/jenkins_scan.py
fi

echo "완료. 산출물은 internal/reports/ 참고."
