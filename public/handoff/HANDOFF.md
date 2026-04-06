# XEIZE API Handoff

## 목적

XEIZE Open API **인증·베이스 URL·비밀 전달 규칙**을 다른 LLM·작업자에게 바로 넘기기 위한 **짧은 요약**이다. 저장소 전체 파이프라인·스크립트 목록·Runbook은 **`internal/docs/PROJECT-OVERVIEW.md`**, 에이전트 진입은 **`AGENT.md`** 를 본다.

## 작업 디렉터리

- 기본: 저장소 루트 (`scripts/`, `public/`, `internal/`, `.env`)

## 환경 변수 (`.env`)

| 변수 | 용도 |
|------|------|
| `XEIZE_API_KEY` | XEIZE Bearer 토큰 (필수) |
| `XEIZE_BASE_URL` | XEIZE Open API base URL (값은 `.env`에만 둔다) |
| `PNET_COOKIE` | `scripts/check_employee_status.py` — pnet 세션 (`curl -b` 형식). 샘플: `public/.env.example` |

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

## 이 저장소에서 XEIZE를 쓰는 스크립트 (요약)

| 스크립트 | 역할 |
|----------|------|
| `scripts/canisterworm_analysis.py` | 프로젝트·취약점·CVE 조회, impact MD |
| `scripts/canisterworm_lockfile_scan.py` | git credential로 lockfile 스캔 |
| `scripts/bitbucket_full_scan.py` | Bitbucket 전수, axios lock + package.json semver 위험 |
| `scripts/fetch_committers.py` | 스캔 JSON에 커미터 병합 |
| `scripts/check_employee_status.py` | pnet 재직·`pnet_dept` 등 |
| `scripts/report_axios_by_team.py` | axios 리포 팀별 MD (`pnet_dept` 우선) |
| `scripts/run_full_pipeline.sh` | §4 순서 일괄 실행 (`--with-pnet`, `--with-lockfile`) |

## 문서·가이드 (웹 API 문서 vs 본 파일)

- 제품 **API Reference** 웹 페이지는 로그인 없이 전체가 안 열릴 수 있다. 그럴 때는 로컬 `public/api-spec/api-1.yaml` 과 위 스크립트가 사실상의 스펙 소스다.

## 다른 LLM용 짧은 프롬프트

```text
작업 디렉터리는 저장소 루트다. XEIZE 연동은 public/handoff/HANDOFF.md 와 internal/docs/PROJECT-OVERVIEW.md 를 따른다.

- .env 에 XEIZE_API_KEY, (권장) XEIZE_BASE_URL 이 있다. 값은 출력하지 마라.
- 인증: Authorization: Bearer 토큰.
- 상세 스크립트·실행 순서·산출물 경로는 internal/docs/PROJECT-OVERVIEW.md §2·§4 를 읽어라.
```
