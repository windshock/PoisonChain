# Scanner API Handoff

## 목적

이 문서는 이 저장소가 사용하는 **취약점/프로젝트 스캐너 API**의 인증·베이스 URL·비밀 전달 규칙을 다른 작업자나 에이전트에게 짧게 넘기기 위한 요약이다. 공개 저장소 기준으로는 이 파일만 읽어도 API 호출 방식과 관련 스크립트 역할을 이해할 수 있게 유지한다.

## 작업 디렉터리

- 기본: 저장소 루트 (`scripts/`, `public/`, `.env`; 로컬 운영본에는 추가 운영 자료 디렉터리가 함께 있을 수 있음)

## 환경 변수 (`.env`)

| 변수 | 용도 |
|------|------|
| `XEIZE_API_KEY` | 스캐너 API Bearer 토큰 (필수) |
| `XEIZE_BASE_URL` | 스캐너 API base URL (값은 `.env`에만 둔다) |
| `HR_PORTAL_COOKIE` | `scripts/check_employee_status.py` — HR 포털 세션 (`curl -b` 형식). 샘플: `public/.env.example` |

비밀값은 프롬프트·로그·커밋에 넣지 말고 `<REDACTED>` 로만 언급한다. 에이전트는 같은 워크스페이스면 `.env` 를 읽게만 지시한다.

## 호출 규칙

- Header: `Authorization: Bearer <XEIZE_API_KEY>`
- Base URL: `XEIZE_BASE_URL`

```bash
curl -sS -H "Authorization: Bearer $XEIZE_API_KEY" \
  "$XEIZE_BASE_URL/projects"
```

## 로컬 API 정의

- OpenAPI: `public/api-spec/api-1.yaml`
- 자주 쓰는 path 예: `projects`, `vulnerabilities`, `git/credentials`, `cves/{cveId}` — 경로·스키마는 YAML 기준.

## 이 저장소에서 스캐너 API를 쓰는 스크립트 (요약)

| 스크립트 | 역할 |
|----------|------|
| `scripts/canisterworm_analysis.py` | 프로젝트·취약점·CVE 조회, impact MD |
| `scripts/canisterworm_lockfile_scan.py` | git credential로 lockfile 스캔 |
| `scripts/bitbucket_full_scan.py` | Bitbucket 전수, axios lock + package.json semver 위험 |
| `scripts/fetch_committers.py` | 스캔 JSON에 커미터 병합 |
| `scripts/check_employee_status.py` | HR 재직·`hr_dept` 등 |
| `scripts/report_axios_by_team.py` | axios 리포 팀별 MD (`hr_dept` 우선) |
| `scripts/run_full_pipeline.sh` | §4 순서 일괄 실행 (`--with-hr`, `--with-lockfile`) |

## 문서·가이드

- 제품 API 문서가 로그인이나 제한된 접근을 요구할 수 있다. 그럴 때는 로컬 `public/api-spec/api-1.yaml` 과 위 스크립트를 사실상의 스펙 소스로 본다.

## 다른 LLM용 짧은 프롬프트

```text
작업 디렉터리는 저장소 루트다. API 연동은 public/handoff/HANDOFF.md 를 따른다.

- .env 에 XEIZE_API_KEY, (권장) XEIZE_BASE_URL 이 있다. 값은 출력하지 마라.
- 인증: Authorization: Bearer 토큰.
- 상세 스크립트와 산출물 경로는 저장소의 README 와 public/README.md 를 우선 참고하라.
```
