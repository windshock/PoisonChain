# Public Assets

`public/` 아래에는 외부 공유 가능한 자산만 둔다.

- `api-spec/`: XEIZE API 로컬 스펙 사본
- `dist/`: 바로 배포 가능한 패키지 (`jenkins-scan-kit.zip`)
- `docs/`: 공개 가능한 가이드
- `evidence/`: 공개 가능한 증적 패키지와 메타데이터
- `handoff/`: XEIZE 환경 변수 전달용 짧은 문서
- `lab/`: 재현용 실험 랩

공개 전 확인 기준:
- 내부 IP, 개인 식별자, 실제 운영 URL이 없어야 한다.
- `.env` 값이나 세션 쿠키는 포함하지 않는다.
