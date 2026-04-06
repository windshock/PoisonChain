# PoisonChain Lab

`public/lab/`는 npm 해석과 Jenkins 스캔 동작을 재현하기 위한 공개용 실험 모음이다.

## 구성

- `public/lab/jenkins/`: 로컬 Jenkins Docker 랩. `scripts/jenkins_scan.py`가 어떤 Job/SCM 패턴을 읽는지 검증할 때 사용
- `public/lab/caret-021-only/`: `axios: ^0.21.0`이 0.30.x로 자동 상향되지 않는지 확인하는 최소 케이스

## semver 실험

```bash
cd public/lab/caret-021-only
npm install
npm ls axios
```

기준 결과:
- `"axios": "^0.21.0"` 단독이면 `axios@0.21.4`
- 0.y.z에서 `^0.21.0` 범위는 `>=0.21.0 <0.22.0`
- 따라서 `npm install`만으로 0.30.x로 자동 상향되지는 않는다

`package-lock.json`은 재현용으로 유지할 수 있지만 `node_modules/`는 로컬 산출물로 본다.
