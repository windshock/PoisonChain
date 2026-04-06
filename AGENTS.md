# Agent instructions (canisterworm)

일부 도구는 이 파일명(`AGENTS.md`)을 읽는다. [`AGENT.md`](AGENT.md)와 동일한 지침이며, 한 저장소에서 둘 다 유지한다.

이 디렉터리는 **웹/서비스 앱이 아니라** 공급망 영향 분석용 저장소다. XEIZE Open API, Bitbucket, (선택) 내부 포털을 호출해 스캔·보고서·메일 초안을 만든다.

## 일괄 실행

- `./scripts/run_full_pipeline.sh` — §4 순서(옵션: `--with-pnet`, `--with-lockfile`).

## 먼저 읽을 문서

| 순서 | 파일 | 내용 |
|------|------|------|
| 1 | `internal/docs/PROJECT-OVERVIEW.md` | 구조, 스크립트, Runbook(§4), 검증 체크리스트 |
| 2 | `internal/docs/LLM-HANDOFF.md` | 다른 세션에 넘길 때 쓸 프롬프트 템플릿 |
| 3 | `public/handoff/HANDOFF.md` | XEIZE 베이스 URL·Bearer 인증 요약 |

## 핵심 경로

- **스크립트:** `scripts/` 아래 (`canisterworm_analysis.py`, `bitbucket_full_scan.py`, `jenkins_scan.py` 등)
- **공개 자산:** `public/` 아래 (`api-spec/`, `dist/`, `evidence/`, `lab/`, 공개 문서)
- **내부 산출:** `internal/reports/`, `internal/emails/`, `internal/config/`, `internal/docs/`
- **API 스펙(로컬):** `public/api-spec/api-1.yaml`

## 운영 규칙

- **비밀:** `XEIZE_API_KEY` 등은 `.env`에만 둔다. 대화·커밋·로그에 실키를 넣지 않는다.
- **재직 조회:** `PNET_COOKIE`는 `.env`에만 둔다(값을 설명/커밋에 넣지 말 것).
- **변경 범위:** 요청한 작업에 필요한 파일만 수정한다. 불필요한 대규모 리팩터·무관한 문서 생성은 하지 않는다.

## 환경

- `.env` 예: `XEIZE_API_KEY`, `XEIZE_BASE_URL`; 재직 조회 스크립트는 **`PNET_COOKIE`**(pnet 세션, `curl -b` 형식). 샘플은 `public/.env.example` 참고.
