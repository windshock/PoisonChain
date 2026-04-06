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

`risk_level`이 **CRITICAL** 또는 **HIGH**인 항목을 보안팀에 전달해 주세요.

---

## 결과 위험도 기준

| 위험도 | 의미 |
|--------|------|
| CRITICAL | 공격 시간대 빌드 + npm install + axios 사용 확인 |
| HIGH | 공격 시간대 빌드 + npm install 확인 (axios 미확인) |
| MEDIUM | npm install 있으나 공격 시간대 빌드 없음 |
| LOW | npm install 없음 |

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
