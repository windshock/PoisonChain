# Jenkins 공급망 공격 영향 분석 스캔 도구

axios@1.14.1 공급망 공격(2026-03-31 KST 09:21~12:40) 영향을 받은  
Jenkins 빌드 잡을 자동으로 탐지합니다.

## 요구사항

- Python 3.9 이상 (외부 라이브러리 설치 불필요)
- Jenkins API 토큰 (읽기 전용)

## 빠른 시작 (3단계)

**1. `.env` 파일 생성**

```bash
cp .env.example .env
```

`.env`를 열어 담당 Jenkins URL과 토큰 입력:

```
JENKINS_URL=https://your-jenkins.example.com
JENKINS_TOKEN=your-username:11abc123def456789
```

**2. 스캔 실행**

```bash
python3 jenkins_scan.py
```

**3. 결과 확인**

```bash
cat reports/jenkins-scan-result.json
```

`reports/jenkins-scan-result.json`의 `summary`와 `results`를 함께 확인하세요.

- `matched_repos`: 현재 스캔에서 Bitbucket 리포와 매칭된 **고유 리포 수**
- `matched_jobs`: 한 리포에 여러 Jenkins 잡이 잡히는 경우까지 포함한 **매칭 잡 수**
- `summary.risk_counts`: 위험도별 잡 수

> 이 키트는 보통 **단일 Jenkins**를 스캔하므로 결과는 `partial_scan: true` 인 **부분 수집본**이다.  
> 조직 전체 수치처럼 사용하지 말고, **해당 Jenkins에서 확인된 결과만** 회신해야 한다.

---

## 결과 위험도 기준

| 위험도 | 의미 |
|--------|------|
| CRITICAL | semver 위험 axios 리포 + 공격 시간대 빌드 + `npm install` 가능 |
| HIGH | semver 위험 axios 리포 + 공격 시간대 이후 빌드 + `npm install` 가능 |
| MEDIUM | semver 위험 axios 리포 + `npm ci` 사용 또는 Jenkinsfile 내부라 명령이 보수적으로 해석됨 |
| LOW | semver 위험 리포와 매칭되지 않았거나 `npm install` 흔적이 없음 |

## 토큰 발급 방법

1. Jenkins 로그인
2. 우측 상단 계정명 클릭 → `Configure`
3. `API Token` 섹션 → `Add new Token`
4. 이름: `security-scan-20260402` → 생성
5. 발급된 토큰을 `.env`의 `JENKINS_TOKEN`에 입력

> **점검 완료 후 7일 이내 토큰 폐기 요청 바랍니다.**

## 로컬 테스트 (localhost:18080)

```bash
python3 jenkins_scan.py --lab
```

## 문의

Security Team (security-team@example.com)
