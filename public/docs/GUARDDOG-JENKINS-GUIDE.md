# GuardDog × Jenkins 통합 가이드

> **대상:** Jenkins 담당자, DevSecOps 팀  
> **작성 배경:** 2026년 3월 axios@1.14.1 공급망 공격 대응  
> **관련 파일:** `public/lab/jenkins/` (PoisonChain 테스트 랩), `public/dist/jenkins-scan-kit/`

---

## 목차

1. [개요 — 왜 GuardDog인가](#1-개요--왜-guarddog인가)
2. [설치 방법](#2-설치-방법)
3. [FreeStyle 잡 통합](#3-freestyle-잡-통합)
4. [Pipeline 잡 통합 (Declarative)](#4-pipeline-잡-통합-declarative)
5. [Shared Library 방식](#5-shared-library-방식)
6. [실패 처리 정책](#6-실패-처리-정책)
7. [다중 Jenkins 인스턴스 적용 고려사항](#7-다중-jenkins-인스턴스-적용-고려사항)
8. [FAQ](#8-faq)

---

## 1. 개요 — 왜 GuardDog인가

### 사고 개요 (2026년 3월)

- **axios@1.14.1** 이 npm에 정상 패키지인 척 배포됨.
- 실제 페이로드는 **`plain-crypto-js@4.2.1`** 이 함께 주입됨. 이 패키지는 `package.json`의 `postinstall` 훅(`"postinstall": "node setup.js"`)으로 `npm install` 시점에 악성 코드를 즉시 실행.
- 기존 CVE DB, npm audit 은 **이미 알려진 취약점**만 차단하므로 이 공격을 탐지하지 못함.

### GuardDog의 차별점

| 도구 | 방식 | 등록 안 된 악성 탐지 |
|------|------|----------------------|
| npm audit | CVE DB 조회 | ❌ |
| Snyk / Dependabot | 알려진 취약 버전 DB | ❌ |
| **GuardDog** | **소스코드 패턴 분석** | ✅ |

GuardDog은 패키지 소스를 직접 내려받아 다음 패턴을 분석한다:
- `postinstall` / `preinstall` 스크립트에서 네트워크 호출, 파일 쓰기, eval
- 난독화된 base64 코드 실행
- 비정상적인 typosquatting 패키지명

`plain-crypto-js@4.2.1` 의 `postinstall: "node setup.js"` 패턴은 GuardDog의 **npm-install-script** 규칙으로 탐지 가능하다.

---

## 2. 설치 방법

### 방법 A — Docker 방식 (권장, 빌드 이슈 없음)

서버에 Docker가 설치되어 있으면 이 방식이 가장 간단하다.

```bash
# GuardDog 이미지 풀
docker pull ghcr.io/datadog/guarddog

# 래퍼 스크립트 생성 (PATH에 등록)
sudo tee /usr/local/bin/guarddog > /dev/null << 'EOF'
#!/bin/sh
docker run --rm -v "$(pwd):/workspace" -w /workspace ghcr.io/datadog/guarddog "$@"
EOF
sudo chmod +x /usr/local/bin/guarddog

# 동작 확인
guarddog --version
```

### 방법 B — pip 방식 (Debian/Ubuntu)

```bash
# 빌드 의존성 (pygit2 컴파일 필요)
sudo apt-get install -y python3 python3-pip libgit2-dev build-essential pkg-config cmake

# GuardDog 설치
sudo pip3 install guarddog --break-system-packages   # Debian bookworm 이상

# 동작 확인
guarddog --version
```

> **주의:** `libgit2` 버전 불일치로 pygit2 빌드가 실패하는 경우가 있다. 그럴 때는 방법 A(Docker)를 사용한다.

### Jenkins Dockerfile에 통합 (Docker 방식)

```dockerfile
FROM jenkins/jenkins:2.492.2-lts-jdk17

USER root
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends docker.io && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN printf '#!/bin/sh\ndocker run --rm -v "$(pwd):/workspace" -w /workspace ghcr.io/datadog/guarddog "$@"\n' \
    > /usr/local/bin/guarddog && chmod +x /usr/local/bin/guarddog

USER jenkins
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt
COPY jobs/ /usr/share/jenkins/ref/jobs/
```

컨테이너 실행 시 **Docker socket을 마운트**해야 래퍼가 동작한다:

```yaml
# docker-compose.yml
services:
  jenkins:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - jenkins_home:/var/jenkins_home
```

---

## 3. FreeStyle 잡 통합

Jenkins 웹 UI → 잡 설정 → **빌드 전 단계(Pre-build Step) → Execute shell** 추가:

```bash
#!/bin/bash
set -e

echo "=== GuardDog 보안 스캔 ==="

if [ ! -f package-lock.json ]; then
  echo "package-lock.json 없음 - 스캔 건너뜀"
  exit 0
fi

# npm 패키지 스캔
guarddog npm verify package-lock.json 2>&1
GUARDDOG_EXIT=$?

if [ $GUARDDOG_EXIT -ne 0 ]; then
  echo "⚠️  GuardDog 경고: 악성 패키지 의심"
  # 정책에 따라 선택:
  # exit 1   # 빌드 강제 실패 (권장: 안정화 후)
  exit 0     # 경고만, 빌드 계속 (초기 도입 시 권장)
fi

echo "✅ GuardDog: 이상 없음"
```

Python 패키지 사용 시:

```bash
# requirements.txt 가 있는 경우
if [ -f requirements.txt ]; then
  guarddog pypi verify requirements.txt 2>&1
fi
```

---

## 4. Pipeline 잡 통합 (Declarative)

### 기본 통합

```groovy
pipeline {
    agent any
    stages {
        stage('GuardDog Security Scan') {
            steps {
                sh '''
                    if [ -f package-lock.json ]; then
                        echo "=== GuardDog npm 스캔 ==="
                        guarddog npm verify package-lock.json 2>&1 || true
                    fi
                '''
            }
        }
        stage('Build') {
            steps {
                sh 'npm ci'
            }
        }
    }
}
```

### JSON 출력 파싱 + 빌드 상태 제어

```groovy
pipeline {
    agent any
    stages {
        stage('GuardDog Security Scan') {
            steps {
                script {
                    if (!fileExists('package-lock.json')) {
                        echo 'package-lock.json 없음 - 건너뜀'
                        return
                    }

                    def scanResult = sh(
                        script: 'guarddog npm verify package-lock.json --output-format json 2>/dev/null || true',
                        returnStdout: true
                    ).trim()

                    if (!scanResult) return

                    def json = readJSON text: scanResult
                    def issues = json.collect { pkg, data ->
                        data.get('issues', []).collect { issue ->
                            "[${issue.severity}] ${pkg}: ${issue.name}"
                        }
                    }.flatten()

                    if (issues) {
                        echo "⚠️  GuardDog 경고:"
                        issues.each { echo "  ${it}" }
                        unstable("GuardDog 보안 경고 발견 - 패키지 확인 필요")
                        // 강제 차단 시: error("GuardDog: 악성 패키지 탐지")
                    } else {
                        echo "✅ GuardDog: 이상 없음"
                    }
                }
            }
        }
        stage('npm install') {
            steps {
                sh 'npm ci'
            }
        }
    }
    post {
        always {
            echo "GuardDog 스캔 완료"
        }
    }
}
```

---

## 5. Shared Library 방식

여러 Jenkins 인스턴스에 각각 설정하는 대신, 중앙 Shared Library로 관리하면 정책 변경 시 한 곳에서 일괄 적용된다.

### 5.1 Shared Library 구조 (Git/SCM)

```
jenkins-shared-library/
├── vars/
│   ├── guardDogScan.groovy      # 메인 스텝
│   └── guardDogScanPypi.groovy  # Python 패키지용
└── README.md
```

### 5.2 `vars/guardDogScan.groovy`

```groovy
/**
 * GuardDog npm 패키지 보안 스캔
 *
 * 사용:
 *   guardDogScan()
 *   guardDogScan(failOnIssue: true, lockfile: 'frontend/package-lock.json')
 *
 * 파라미터:
 *   failOnIssue  (boolean, 기본 false) - true 시 탐지되면 빌드 실패
 *   lockfile     (string, 기본 'package-lock.json') - 스캔할 lockfile 경로
 *   excludeRules (list, 기본 []) - 제외할 GuardDog 규칙 (e.g. ['npm-install-script'])
 */
def call(Map config = [:]) {
    def failOnIssue  = config.get('failOnIssue', false)
    def lockfile     = config.get('lockfile', 'package-lock.json')
    def excludeRules = config.get('excludeRules', [])

    if (!fileExists(lockfile)) {
        echo "GuardDog: ${lockfile} 없음 - 건너뜀"
        return
    }

    def excludeFlag = excludeRules
        ? excludeRules.collect { "--exclude-rules ${it}" }.join(' ')
        : ''

    def exitCode = sh(
        script: "guarddog npm verify ${lockfile} ${excludeFlag} 2>&1",
        returnStatus: true
    )

    if (exitCode != 0) {
        if (failOnIssue) {
            error "GuardDog: 악성 패키지 탐지 - 빌드 중단 (${lockfile})"
        } else {
            unstable("GuardDog: 보안 경고 발견 (${lockfile}) - 확인 필요")
        }
    } else {
        echo "✅ GuardDog: ${lockfile} 이상 없음"
    }
}
```

### 5.3 `vars/guardDogScanPypi.groovy`

```groovy
def call(Map config = [:]) {
    def failOnIssue   = config.get('failOnIssue', false)
    def requirementsFile = config.get('requirementsFile', 'requirements.txt')

    if (!fileExists(requirementsFile)) {
        echo "GuardDog: ${requirementsFile} 없음 - 건너뜀"
        return
    }

    def exitCode = sh(
        script: "guarddog pypi verify ${requirementsFile} 2>&1",
        returnStatus: true
    )

    if (exitCode != 0) {
        if (failOnIssue) {
            error "GuardDog: 악성 Python 패키지 탐지 - 빌드 중단"
        } else {
            unstable("GuardDog: Python 패키지 보안 경고 발견")
        }
    }
}
```

### 5.4 각 잡에서 사용

```groovy
@Library('company-shared-lib@main') _

pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                // 기본: 경고만, 빌드 계속
                guardDogScan()

                // 강제 차단 + 특정 lockfile
                // guardDogScan(failOnIssue: true, lockfile: 'client/package-lock.json')

                // postinstall 규칙 예외 (husky 같은 정상 패키지 있을 때)
                // guardDogScan(excludeRules: ['npm-install-script'])
            }
        }
        stage('Build') {
            steps {
                sh 'npm ci && npm run build'
            }
        }
    }
}
```

### 5.5 Jenkins 전역 설정에서 Shared Library 등록

**Manage Jenkins → Configure System → Global Pipeline Libraries:**

| 항목 | 값 |
|------|-----|
| Name | `company-shared-lib` |
| Default version | `main` |
| Retrieval method | Modern SCM → Git |
| Repository URL | `https://git.example.com/devops/jenkins-shared-library.git` |

---

## 6. 실패 처리 정책

### 단계별 도입 권장

| 단계 | 기간 | 설정 | 효과 |
|------|------|------|------|
| **Phase 1 — 모니터링** | 2-4주 | `failOnIssue: false` | 경고만, 빌드 계속. 오탐 파악 |
| **Phase 2 — 소프트 차단** | 2-4주 | `failOnIssue: false` + Slack 알림 | Unstable 상태로 팀에 통보 |
| **Phase 3 — 하드 차단** | 이후 | `failOnIssue: true` | 탐지 시 빌드 실패, 배포 차단 |

### 예외 규칙 목록 관리

정상 패키지가 오탐되는 경우 Shared Library에 허용 목록으로 관리:

```groovy
// 공통 허용 목록 (vars/guardDogScan.groovy 내부 또는 별도 설정 파일)
def DEFAULT_EXCLUDE_RULES = [
    // 정상 패키지의 postinstall 스크립트 (node-gyp, husky 등)
    // ⚠️ 추가 전 반드시 팀 리뷰 필요
]
```

### 규칙별 판단 기준

| GuardDog 규칙 | 위험도 | 기본 정책 |
|---------------|--------|-----------|
| `npm-install-script` | HIGH | 차단 권장 |
| `obfuscated-code` | CRITICAL | 즉시 차단 |
| `env-exfiltration` | CRITICAL | 즉시 차단 |
| `typosquatting` | MEDIUM | 경고 후 리뷰 |
| `http-exfiltration` | HIGH | 차단 권장 |

---

## 7. 다중 Jenkins 인스턴스 적용 고려사항

### 7.1 적용 우선순위

**PoisonChain Jenkins 스캔 결과** (`reports/jenkins-scan-result.json` 또는 중앙 수집 JSON 기준):

1. **즉시 (CRITICAL/HIGH):** semver 위험 81개 리포의 Jenkins 잡
2. **1-2주 내:** npm/yarn 빌드 잡 전체
3. **1개월 내:** 나머지 잡 (Python requirements.txt 포함)

```bash
# CRITICAL 잡 목록 추출
jq '.results[] | select(.risk_level == "CRITICAL") | .job_name' reports/jenkins-scan-result.json
```

### 7.2 폐쇄망 Jenkins 대응

인터넷이 안 되는 Jenkins 인스턴스의 경우 GuardDog 이미지를 private 레지스트리에 미러링한다.

```bash
# 인터넷 가능한 서버에서 (1회)
docker pull ghcr.io/datadog/guarddog
docker save ghcr.io/datadog/guarddog | gzip > guarddog-image.tar.gz

# private 레지스트리로 전송 후 push
docker load < guarddog-image.tar.gz
docker tag ghcr.io/datadog/guarddog registry.example.com/guarddog:latest
docker push registry.example.com/guarddog:latest
```

래퍼 스크립트에서 private 레지스트리 이미지 사용:

```bash
#!/bin/sh
docker run --rm \
  -v "$(pwd):/workspace" \
  -w /workspace \
  registry.example.com/guarddog:latest "$@"
```

### 7.3 분산 Jenkins 관리 전략

```
중앙 Git 저장소 (devops/jenkins-shared-library)
        │
        ├── Jenkins Instance A (팀 1)  → @Library('company-shared-lib')
        ├── Jenkins Instance B (팀 2)  → @Library('company-shared-lib')
        ├── Jenkins Instance C (팀 3)  → @Library('company-shared-lib')
        └── ...
```

- **정책 변경** 시 Shared Library `vars/guardDogScan.groovy` 1개만 수정하면 전체 적용
- Shared Library 변경은 **PR + 리뷰 필수** (공급망 보안 정책 자체가 변조되지 않도록)

### 7.4 Gradle/Maven 프로젝트 대응

Jenkins 잡이 npm이 아닌 JVM 프로젝트인 경우도 공급망 위험이 있다:

```bash
# pip 패키지 스캔 (빌드 툴에 Python 스크립트 있는 경우)
guarddog pypi verify requirements.txt

# 개별 패키지 검사
guarddog npm scan axios           # 최신 버전 스캔
guarddog npm scan axios@1.14.1    # 특정 버전 스캔
```

### 7.5 Jenkins 에이전트 vs 컨트롤러 배치

| 배치 | 장점 | 단점 |
|------|------|------|
| 컨트롤러에 guarddog 설치 | 설정 간단 | 컨트롤러 부하 |
| **에이전트에 guarddog 설치 (권장)** | 확장성, 격리 | 에이전트 이미지 관리 필요 |
| Docker agent + guarddog 이미지 | 격리 최상 | Docker socket 마운트 필요 |

---

## 8. FAQ

**Q: postinstall 스크립트를 쓰는 정상 패키지(husky, node-gyp 등)도 경고가 뜨나요?**

A: 뜹니다. GuardDog은 보수적으로 탐지하기 때문에 `npm-install-script` 규칙에서 정상 패키지도 걸립니다. `--exclude-rules npm-install-script` 로 규칙을 제외하거나, Shared Library의 허용 목록에 추가하세요. 단, 허용 목록 추가는 반드시 팀 리뷰를 거치세요.

```bash
guarddog npm verify package-lock.json --exclude-rules npm-install-script
```

**Q: 폐쇄망에서 `guarddog npm verify` 가 동작하나요?**

A: `verify` 명령은 패키지 소스를 npmjs.org에서 다운로드하므로 인터넷 연결이 필요합니다. 폐쇄망이면 내부 npm 미러(Nexus, Verdaccio 등)를 구성하고, `--registry` 플래그로 지정하거나 npm 설정에 등록하세요. 이미 다운로드된 tarball은 `guarddog npm scan ./path/to/pkg`로 오프라인 스캔이 가능합니다.

**Q: 이미 `node_modules`가 설치된 프로젝트의 특정 패키지만 의심스러우면?**

A: 개별 패키지 디렉터리를 직접 스캔할 수 있습니다.

```bash
guarddog npm scan ./node_modules/plain-crypto-js
guarddog npm scan ./node_modules/axios
```

**Q: 스캔 결과를 Jenkins에서 리포트로 남길 수 있나요?**

A: JSON 출력을 파일로 저장하고 `archiveArtifacts` 로 보관하세요.

```groovy
sh 'guarddog npm verify package-lock.json --output-format json > guarddog-report.json 2>/dev/null || true'
archiveArtifacts artifacts: 'guarddog-report.json', allowEmptyArchive: true
```

**Q: pip으로 설치 시 `pygit2` 빌드 오류가 납니다.**

A: Debian bookworm (Jenkins LTS 기본 베이스)에서 libgit2 버전 불일치로 발생합니다. Docker 방식(방법 A)을 권장합니다. pip을 고집하는 경우 `libgit2-dev` 버전을 명시하거나 `pygit2` 를 `--no-deps` 없이 설치해 보세요.

**Q: 여러 Jenkins 중 일부만 npm 잡입니다. 나머지는 어떻게 하나요?**

A: `guardDogScan()` 은 `package-lock.json` 이 없으면 자동으로 건너뜁니다. 모든 파이프라인에 넣어도 부작용 없습니다. Python 프로젝트는 `guardDogScanPypi()` 를 추가하세요.

---

## 참고 링크

- [GuardDog GitHub](https://github.com/DataDog/guarddog)
- [GuardDog Rules 목록](https://github.com/DataDog/guarddog/tree/main/guarddog/rules)
- [Axios maintainer post-mortem analysis](./analysis-of-axios-supply-chain-incident-based-on-maintainer-report.md)
- [Axios technical attack report](./axios-npm-supply-chain-attack-report.md)
- [Jenkins Shared Libraries 공식 문서](https://www.jenkins.io/doc/book/pipeline/shared-libraries/)
