# CI/CD 파이프라인 공급망 보안 가이드라인

> **배경**: 2026-03-31 axios@1.14.1 공급망 공격 대응 과정에서 식별된 보안 미흡 사항을 반영한 설정 가이드.  
> **적용 대상**: Jenkins 인스턴스를 운영하며 npm/Python 패키지를 사용하는 팀 또는 조직

---

## 목차

1. [Jenkins 접근 제어](#1-jenkins-접근-제어)
2. [API 토큰 관리](#2-api-토큰-관리)
3. [빌드 환경 보안](#3-빌드-환경-보안)
4. [공급망 공격 대응](#4-공급망-공격-대응)
5. [긴급 점검 체크리스트](#5-긴급-점검-체크리스트)

---

## 1. Jenkins 접근 제어

### 익명 접근 차단

`Manage Jenkins → Security → Authorization`

```
✅ 권장: Matrix-based security 또는 Role-Based Strategy
❌ 금지: Anyone can do anything
```

### CSRF Protection 확인

`Manage Jenkins → Security → CSRF Protection → Enable` 활성화 여부 확인

### Agent → Controller 접근 제어

`Manage Jenkins → Security → Agent → Controller Security` 활성화

---

## 2. API 토큰 관리

### 발급 원칙

| 원칙 | 내용 |
|------|------|
| **최소 권한** | 스캔 전용 토큰은 `Overall/Read + Job/Read + Job/ExtendedRead`만 부여 |
| **용도별 분리** | 빌드 트리거용 / 읽기 전용 / 관리용 분리 발급 |
| **만료 설정** | 일회성 점검 토큰은 7일 이내 폐기 |
| **저장 금지** | 토큰 값을 코드/커밋에 포함 금지 — `.env`에만 저장 |

### 보안 점검용 토큰 발급

**Jenkins 2.129 이상 (신버전):**
1. Jenkins 로그인 → 계정명 클릭 → `Configure`
2. `API Token` → `Add new Token`
3. 이름: `security-scan-readonly-{YYYYMMDD}`
4. 필요 권한 확인: `Overall/Read + Job/Read + Job/ExtendedRead`
5. 발급된 토큰을 `.env`에 입력:
   ```
   JENKINS_URL=https://your-jenkins.example.com
   JENKINS_TOKEN=your-username:발급된토큰
   ```

**Jenkins 2.128 이하 (구버전 — `Add new Token` 없음):**
1. Jenkins 로그인 → 계정명 클릭 → `Configure`
2. `API Token` 섹션 → **`Show API Token`** 클릭
3. 표시된 토큰 값을 복사해서 전달
   > 토큰 교체가 필요하면 `Change API Token` 클릭 (기존 연동 끊길 수 있으니 주의)

### 빌드 로그 보존 기간

각 잡 설정 → `Discard old builds`:
```
Days to keep builds: 30   (팀 정책에 따라 조정)
Max # of builds to keep: 200
```

> ⚠️ 이번 공격(2026-03-31)처럼 소급 조사가 필요한 경우 보존 기간이 짧으면 증거 확보 불가.  
> 현재 기본값이 30일 미만인 경우 즉시 조정 권고.

---

## 3. 빌드 환경 보안

### `npm install` → `npm ci` 전환

| 명령 | 동작 | 보안성 |
|------|------|--------|
| `npm install` | package.json 기반, 최신 버전 해석 | ❌ 공격 버전 자동 설치 가능 |
| `npm ci` | package-lock.json 완전 고정 | ✅ lockfile 버전만 설치 |

```bash
# Jenkinsfile 또는 빌드 스크립트에서 교체
- npm install
+ npm ci
```

단, `npm ci`는 **lockfile에 이미 악성 버전이 기록된 경우에는 막지 못함** → §4 공급망 대응과 병행 필요.

### package-lock.json SCM 커밋 필수

```bash
# .gitignore에서 제거 확인
cat .gitignore | grep package-lock   # 출력 없어야 정상
```

---

## 4. 공급망 공격 대응

### 4.1 신규 패키지 설치 유예 (핵심 권고)

> **이번 공격의 핵심**: axios@1.14.1은 공개되자마자 당일 설치됨.  
> **공개 후 수일 이내 패키지 설치를 제한하면 동일 패턴 차단 가능.**

**npm — Renovate `minimumReleaseAge`**

```json
// renovate.json
{
  "packageRules": [{
    "matchPackagePatterns": ["*"],
    "minimumReleaseAge": "3 days"
  }]
}
```
→ npm 레지스트리 공개 후 3일 미만 버전은 Renovate가 PR을 생성하지 않음.

**npm — private 레지스트리(Nexus/Verdaccio) 정책**

```bash
# .npmrc에서 private 미러 강제
registry=https://registry.example.com/repository/npm-proxy/
```
→ Nexus Smart Proxy 또는 Verdaccio 플러그인으로 age-based 필터 적용.

**Python — uv `exclude-newer` (네이티브 지원)**

```toml
# uv.toml
[tool.uv]
exclude-newer = "2026-03-30T00:00:00Z"
```
→ 지정 일시 이후 공개된 패키지는 resolution 대상에서 완전 제외.  
→ CLI: `uv lock --exclude-newer=2026-03-30`

| 패키지 매니저 | 설정 | 네이티브 |
|-------------|------|---------|
| npm (Renovate) | `minimumReleaseAge` in renovate.json | ✅ |
| npm (레지스트리) | Nexus/Verdaccio 미러 정책 | 간접 |
| Python (uv) | `exclude-newer` in uv.toml | ✅ |
| Python (pip) | 없음 — private PyPI 미러 경유 | ❌ |

### 4.2 postinstall 스크립트 실행 차단

이번 공격 벡터: `plain-crypto-js` postinstall 실행

```bash
# 빌드 스크립트에서 --ignore-scripts 추가
npm ci --ignore-scripts
```

> ⚠️ `--ignore-scripts`는 정상 패키지의 빌드 스텝(node-gyp 등)도 막을 수 있음.  
> 적용 전 해당 프로젝트 빌드 테스트 필수.

### 4.3 패키지 버전 정확히 고정

```json
// package.json
{
  "dependencies": {
    "axios": "1.7.9"    // ✅ 정확한 버전
  }
}
```

### 4.4 GuardDog 파이프라인 통합

상세 내용: `public/docs/GUARDDOG-JENKINS-GUIDE.md`

```groovy
stage('Supply Chain Scan') {
  steps {
    sh '''
      guarddog npm verify \
        $(node -e "const p=require('./package.json');
          console.log(Object.entries({...p.dependencies,...p.devDependencies||{}})
          .map(([k,v])=>k+'@'+v.replace(/[^\\d.]/g,'')).join(' '))")
    '''
  }
}
```

---

## 5. 긴급 점검 체크리스트

### ✅ 즉시 확인 (당일)

- [ ] 공격 기간(2026-03-31 09:21~12:40 KST) 빌드 이력 확인
  ```bash
  # 1. jenkins-scan-kit/.env 파일에 Jenkins URL과 토큰 설정 (최초 1회)
  #    JENKINS_URL=https://your-jenkins.example.com
  #    JENKINS_TOKEN=your-username:11abc123def456789
  cd public/dist/jenkins-scan-kit
  python3 jenkins_scan.py
  # 모든 잡(중첩 폴더 포함) 자동 스캔 → reports/jenkins-scan-result.json
  ```
- [ ] 해당 빌드에 `npm install` 포함 여부 확인
- [ ] 빌드 로그에서 `plain-crypto-js` 관련 출력 여부 확인
  ```bash
  grep -r "plain-crypto\|postinstall" ~/.jenkins/jobs/*/builds/*/log
  ```
- [ ] 빌드 로그 보존 기간 확인 — 30일 미만이면 즉시 조정

### ✅ 단기 조치 (1주일 이내)

- [ ] `npm install` → `npm ci` 전환
- [ ] package-lock.json SCM 커밋 여부 확인
- [ ] Renovate `minimumReleaseAge: "3 days"` 추가 (또는 uv `exclude-newer`)
- [ ] 보안 점검 전용 읽기 전용 토큰 발급 및 전달

### ✅ 중기 조치 (1개월 이내)

- [ ] GuardDog 파이프라인 통합 (`docs/GUARDDOG-JENKINS-GUIDE.md`)
- [ ] private npm 미러(Nexus/Artifactory) 레지스트리 고정
- [ ] prod zone Jenkins 서버 외부 통신 방화벽 정책 검토

---

## 참고 문서

| 문서 | 위치 | 내용 |
|------|------|------|
| GuardDog 통합 가이드 | `docs/GUARDDOG-JENKINS-GUIDE.md` | npm 패키지 자동 보안 스캔 설정 |
| 메인테이너 포스트모템 분석 | `docs/analysis-of-axios-supply-chain-incident-based-on-maintainer-report.md` | 배포 체인과 계정/단말 침해 관점 분석 |
| 공급망 공격 기술 분석 | `docs/axios-npm-supply-chain-attack-report.md` | 페이로드, RAT, IOC 중심 분석 |
| Jenkins 스캔 키트 | `dist/jenkins-scan-kit/README.md` | 개별 Jenkins 빌드 이력 자동 분석 도구 |

---

*작성: PoisonChain canisterworm-analysis | 2026-04-02*
