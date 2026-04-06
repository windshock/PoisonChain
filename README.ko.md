# PoisonChain 🔗☠️

[English](README.md)

**악성 npm 패키지가 퍼블리시됐다. 우리 조직에서 영향받는 저장소는 몇 개이고, 누가 관리하며, 어떤 빌드가 공격 시간대에 실행됐는가?**

PoisonChain은 npm 공급망 공격이 발생했을 때 **조직 전체의 폭발 반경(blast radius)을 자동으로 계산**하는 분석 도구다. 수천 개 저장소를 스캔해서 영향받는 프로젝트·담당자·빌드 파이프라인을 한 번에 파악하고, 팀별 대응 보고서까지 만들어 준다.

> 수작업으로 수주일 걸릴 영향 분석을 **2시간 안에** 끝낸다.

---

## 왜 빌드 로그 기반인가

이 공격의 핵심은 **증거 인멸**이다. 악성 `postinstall` 훅이 실행되면:

1. 플랫폼별 RAT(원격 접근 트로이목마)를 다운로드·실행한 뒤
2. `setup.js`(드로퍼)를 삭제하고
3. 악성 `package.json`을 정상 v4.2.0 스텁으로 교체한다

개발자가 `npm install` 완료 후 `node_modules`를 확인해도 이상한 점이 보이지 않는다. 파일시스템에 흔적이 남지 않으므로, 사후에 lockfile이나 소스 트리만 분석해서는 **실제 감염 여부를 판단할 수 없다.**

반면 **Jenkins 빌드 로그는 공격 시점에 어떤 명령이 실행됐는지 불변 기록으로 남아 있다.** 공격 시간대(2026-03-31 00:21~03:51 UTC)에 `npm install`을 실행한 빌드가 있다면, 그 환경은 감염된 것으로 봐야 한다.

실제 대응 과정에서 lockfile 기반 분석만으로는 한계가 분명했다:

- **Docker 빌드에서 이전 lockfile을 덮어쓰는 경우** — 실제 빌드된 의존성 버전과 lockfile이 불일치
- **서버 배포본에 lockfile이 포함되지 않는 경우** — 운영 서버에서 감염 여부 확인 불가
- **Bitbucket에 커밋된 lockfile이 최신이 아닌 경우** — 개발자 PC나 CI에서 빌드된 실제 lockfile이 저장소에 반영 안 됨

"지금 코드가 어떤 상태인지"가 아니라 **"그때 빌드 환경에서 실제로 무엇이 실행됐는지"**가 감염 판단의 기준이고, 그 기록은 Jenkins 빌드 로그에만 남아 있다. PoisonChain이 Jenkins 빌드 로그 분석에 집중하는 이유가 여기에 있다.

> 공격 배경에 대한 자세한 분석은 아래 참고:
> - [Hunt.io — Axios Supply Chain Attack: TA444/BlueNoroff](https://hunt.io/blog/axios-supply-chain-attack-ta444-bluenoroff)
> - [Endor Labs — npm axios Compromise](https://www.endorlabs.com/learn/npm-axios-compromise)
>
> 이 공격의 C2 서버(`sfrclak.com` → Hostwinds AS54290)는 암호화폐 결제를 지원하는 익명 VPS에 호스팅되었다. C2 탐지 규칙과 IP 대역은 [windshock/anonymous-vps](https://github.com/windshock/anonymous-vps) 참고.

---

## 어떤 문제를 푸는가

2026년 3월, `axios@1.14.1`과 `plain-crypto-js@4.2.1`이 npm에 악성 버전으로 퍼블리시됐다. `postinstall` 훅을 통해 npm 토큰, GitHub PAT, SSH 키 등을 탈취하는 공급망 공격이었다.

이때 보안팀이 답해야 할 질문:

| 질문 | PoisonChain이 하는 일 |
|------|----------------------|
| 감염된 저장소가 몇 개인가? | Bitbucket 전체 스캔 → lockfile에서 악성 버전 탐지 |
| `npm install` 하면 새로 감염될 수 있는 저장소는? | semver 범위 분석 (`^1.14.0`이 `1.14.1`을 끌어올 수 있는지) |
| 각 저장소 담당자가 누구인가? | 최근 커미터 추출 + HR 시스템 연동(재직/퇴직 확인) |
| 공격 시간대에 어떤 빌드가 실행됐나? | Jenkins 인스턴스 일괄 스캔, `npm install` vs `npm ci` 구분 |
| 팀별로 정리된 대응 보고서가 필요하다 | 팀·저장소·리스크 레벨별 대시보드 자동 생성 |

---

## 파이프라인 흐름

```
악성 패키지 퍼블리시
        │
        ▼
┌─ canisterworm_analysis.py ──┐   XEIZE 취약점 DB에서 IOC 매칭
│  CanisterWorm 캠페인 46개    │   → 직접 매칭 + IOC 키워드 검색
│  패키지 + IOC 키워드 검색     │
└─────────────┬───────────────┘
              ▼
┌─ bitbucket_full_scan.py ────┐   Bitbucket 전체 저장소 스캔
│  lockfile 파싱 + semver 분석 │   → 감염 확정 / semver 리스크 분류
└─────────────┬───────────────┘
              ▼
┌─ fetch_committers.py ───────┐   저장소별 최근 커미터 추출
│  + check_employee_status.py │   → 이름·이메일·팀·재직 여부
└─────────────┬───────────────┘
              ▼
┌─ jenkins_scan.py ───────────┐   Jenkins 인스턴스 일괄 스캔
│  공격 시간대 빌드 교차 분석   │   → npm install 사용 여부 + 리스크 등급
└─────────────┬───────────────┘
              ▼
┌─ report_axios_by_team.py ───┐   팀별 대시보드 + 대응 보고서
│  경영진 보고 + IR 패키지      │   → Markdown 보고서 일괄 생성
└─────────────────────────────┘
```

한 번에 실행:
```bash
./scripts/run_full_pipeline.sh --with-hr --with-lockfile
```

---

## 빠른 시작

```bash
# 1. 클론
git clone https://github.com/<your-org>/PoisonChain.git
cd PoisonChain

# 2. 환경변수 설정
cp public/.env.example .env
# .env를 열어 XEIZE_API_KEY 등을 입력

# 3. 파이프라인 실행
./scripts/run_full_pipeline.sh --help     # 옵션 확인
./scripts/run_full_pipeline.sh            # 기본 실행
```

**요구 사항:** Python 3.9+, `requests` 라이브러리, 분석 대상 API 접근 권한

> **참고:** 이 저장소의 스크립트는 특정 내부 시스템(Bitbucket, Jenkins, 자체 취약점 스캐너 API)에 맞춰 작성되었다. 다른 조직은 GitHub/GitLab, GitHub Actions/CircleCI, Snyk/Dependabot, Okta/AD 등 다른 시스템을 사용할 것이다. 이 프로젝트의 가치는 특정 API 호출이 아니라 **방법론과 파이프라인 로직**에 있다. Fork 후 각자 환경에 맞게 연동 부분을 수정해서 사용하면 된다.

---

## 스크립트 설명

| 스크립트 | 역할 | 입력 | 출력 |
|----------|------|------|------|
| `canisterworm_analysis.py` | CanisterWorm 캠페인(46개 패키지) IOC 매칭 | XEIZE API | 영향 보고서 |
| `bitbucket_full_scan.py` | 전체 저장소 lockfile 스캔 + semver 리스크 | Bitbucket API | 저장소별 감염/리스크 JSON |
| `canisterworm_lockfile_scan.py` | 실제 lockfile을 git에서 가져와 정밀 스캔 | Git PAT | 패키지별 매칭 보고서 |
| `fetch_committers.py` | 저장소별 최근 커미터 추출 | Bitbucket API | 커미터 정보 JSON |
| `check_employee_status.py` | 커미터 재직/퇴직 여부 확인 | HR 포털 | 상태 어노테이션 |
| `jenkins_scan.py` | 공격 시간대 빌드 파이프라인 분석 | Jenkins API | 잡별 리스크 등급 JSON |
| `report_axios_by_team.py` | 팀별 대시보드 생성 | 위 결과물 전체 | Markdown 보고서 |
| `preserve_evidence.py` | 악성 패키지 아카이브 + SHA 검증 | npm/Datadog/GitHub | 포렌식 증거 번들 |
| `verify_repos.py` | 삭제/제외 저장소 정리 | 스캔 결과 JSON | 정제된 JSON |

---

## 로컬 랩 환경

`public/lab/`에 Docker 기반 테스트 환경이 포함되어 있다. 실제 인프라 없이 스크립트 로직을 검증할 수 있다.

```bash
cd public/lab/jenkins
docker compose up -d --build
# Jenkins: http://localhost:18080
```

11개 사전 구성된 Jenkins 잡으로 `jenkins_scan.py`의 리스크 판정 로직을 테스트할 수 있다:
- `axios-semver-risk` — `npm install` + semver 리스크 → CRITICAL
- `axios-safe` — 안전한 버전 고정 → LOW
- `no-axios-java` — Java 빌드 → npm 무관

semver 엣지 케이스 테스트:
```bash
cd public/lab/caret-021-only
npm install && npm ls axios    # ^0.21.0이 0.30.x를 끌어오지 않는지 확인
```

---

## 개발자 셀프 스캔 키트

`public/dist/jenkins-scan-kit.zip`은 개발팀에 직접 배포할 수 있는 **독립 실행형 스캔 도구**다. 외부 라이브러리 설치 없이 Python 3.9만 있으면 된다.

```
jenkins-scan-kit/
├── jenkins_scan.py              # 스캔 스크립트 (단일 파일)
├── config/jenkins-instances.json # 스캔 대상 Jenkins 목록
├── .env.example                 # 환경변수 템플릿
├── reports/                     # 결과 출력 디렉터리
└── README.md                    # 3단계 가이드
```

**운영 흐름:**
1. 보안팀이 개발팀 담당자에게 zip + 토큰 발급 안내 메일 발송
2. 담당자가 `.env`에 자기 Jenkins URL·토큰 입력 후 `python3 jenkins_scan.py` 실행
3. `reports/jenkins-scan-result.json`에서 `risk_level: CRITICAL/HIGH` 항목을 보안팀에 회신

외부 라이브러리 의존성 없이 동작하므로, 네트워크 제한 환경에서도 사용 가능하다.

---

## 포렌식 증거

`public/evidence/`에 악성 패키지 원본과 해시가 보존되어 있다.

샘플 출처는 Datadog의 공개 악성 패키지 데이터셋([DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset))이며, `preserve_evidence.py`가 자동으로 다운로드·해시 검증·메타데이터 생성을 수행한다.

```
public/evidence/
├── axios@1.14.1/
│   ├── axios-1.14.1.tgz        # 악성 패키지 원본 (Datadog 데이터셋)
│   ├── metadata.json            # 출처, 수집 시각, SHA256/SHA1
│   ├── sha256.txt
│   └── sha1.txt
└── plain-crypto-js@4.2.1/
    └── ...
```

각 `metadata.json`에 수집 출처(`source`)·시각(`acquired_at`)·해시가 기록되어 있으며, SANS에서 공개한 해시와 대조 검증 가능하다.

---

## 프로젝트 구조

```
PoisonChain/
├── scripts/          분석 스크립트 (Python + Shell)
├── public/
│   ├── api-spec/     XEIZE Open API 스펙 (OpenAPI 3.1)
│   ├── dist/         배포용 산출물
│   ├── docs/         Jenkins 보안 가이드, GuardDog 연동 가이드
│   ├── evidence/     포렌식 증거 아카이브
│   ├── handoff/      API 인증 요약
│   └── lab/          Docker 기반 테스트 환경
├── internal/         ⛔ 내부 전용 (보고서, 설정, 메일 초안)
├── .env.example      환경변수 템플릿
└── .env              ⛔ 비밀값 (git 추적 안 됨)
```

---

## 관련 문서

- [`public/handoff/HANDOFF.md`](public/handoff/HANDOFF.md) — XEIZE API 인증 요약
- [`public/docs/JENKINS-SECURITY-GUIDE.md`](public/docs/JENKINS-SECURITY-GUIDE.md) — Jenkins 공급망 보안 가이드
- [`public/docs/GUARDDOG-JENKINS-GUIDE.md`](public/docs/GUARDDOG-JENKINS-GUIDE.md) — GuardDog + Jenkins Shared Library 연동
- [`public/lab/README.md`](public/lab/README.md) — 로컬 랩 환경 설명

---

## 라이선스

MIT
