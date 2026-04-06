# Jenkins Lab — PoisonChain 테스트 환경

`scripts/jenkins_scan.py` 개발·검증을 위한 로컬 Jenkins Docker 환경이다. 실제 사내 배포를 재현하는 랩이 아니라, Job/SCM/config.xml 수집과 위험도 매칭 로직을 검증하는 공개용 테스트 환경이다.

## 빠른 시작

```bash
cd public/lab/jenkins
docker compose up -d --build   # 첫 실행 (플러그인 설치로 2~3분 소요)
docker compose logs -f         # 준비 확인 ("Jenkins is fully up and running" 로그)
```

접속: <http://localhost:18080>  
관리자: `admin` / `admin123`  
익명 읽기: ✅ 허용 (토큰 없이 API 호출 가능)

## 테스트 Job 목록

| Job 이름 | Bitbucket SCM | npm 패턴 | 예상 등급 |
|---------|--------------|---------|---------|
| `axios-semver-risk` | AIDEV2/test-frontend | `npm install` | 🔴 CRITICAL |
| `axios-semver-risk-ci` | AIDEV2/test-frontend-2 | `npm ci` | 🟡 MEDIUM |
| `axios-safe` | OCBDEV/safe-app | `npm install` | 🟢 LOW |
| `no-axios-java` | VASDEV/backend-service | `mvn` | 🟢 LOW |

## API 확인

```bash
# Job 목록
curl -s http://localhost:18080/api/json?tree=jobs[name,url] | python3 -m json.tool

# 특정 Job SCM 정보
curl -s http://localhost:18080/job/axios-semver-risk/config.xml

# jenkins_scan.py 실행
cd ../../..
JENKINS_LAB_URL=http://localhost:18080 python3 scripts/jenkins_scan.py --instance-url http://localhost:18080
```

## 종료 및 초기화

```bash
docker compose down          # 컨테이너 중지 (데이터 보존)
docker compose down -v       # 컨테이너 + 볼륨 삭제 (완전 초기화)
```

## 주의

- 테스트 전용 환경. 비밀번호/토큰을 실제 값으로 바꾸지 말 것.
- Job의 SCM URL은 실제 Bitbucket에 존재하지 않는 가짜 URL이다.
- 빌드는 실행되지 않으며, `config.xml` 파싱과 `internal/reports/data/jenkins-scan-result.json` 생성 테스트가 목적이다.
