# Public Assets

`public/` 아래에는 외부 공유 가능한 자산만 둔다. 이 디렉터리의 일부 파일은 원래 운영 환경과의 호환성을 위해 `XEIZE_*` 변수명과 XEIZE API 스펙 명칭을 그대로 유지한다.

- `api-spec/`: XEIZE API 로컬 스펙 사본
- `dist/`: 바로 배포 가능한 패키지 (`jenkins-scan-kit.zip`)
- `docs/`: 공개 가능한 가이드
- `evidence/`: 공개 가능한 증적 패키지와 메타데이터
- `handoff/`: XEIZE API 환경 변수 전달용 짧은 문서
- `lab/`: 재현용 실험 랩

주요 공개 문서:
- `docs/analysis-of-axios-supply-chain-incident-based-on-maintainer-report.md`: 메인테이너 포스트모템 기반 사고 구조 분석
- `docs/axios-npm-supply-chain-attack-report.md`: 페이로드, RAT, IOC 중심 기술 분석
- `docs/JENKINS-SECURITY-GUIDE.md`: Jenkins 공급망 보안 가이드
- `docs/GUARDDOG-JENKINS-GUIDE.md`: GuardDog Jenkins 통합 가이드

공개 전 확인 기준:
- private IP 대역, 개인 식별자, 실제 운영 URL이 없어야 한다.
- `.env` 값이나 세션 쿠키는 포함하지 않는다.
