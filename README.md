# PoisonChain

[![The 3-Hour Breach: Deconstructing the Axios Supply Chain Attack](https://img.youtube.com/vi/nNCPH2xuIw4/maxresdefault.jpg)](https://youtu.be/nNCPH2xuIw4)

📄 **[Download Presentation Slides (PDF)](public/youtube/PoisonChain.pdf)**

[한국어](README.ko.md)

PoisonChain is an incident-response toolkit for npm supply chain attacks. It answers the questions security teams get first and fastest: which repositories were exposed, who owns them, which builds actually ran during the attack window, and what each team needs to do next.

It combines repository scanning, semver risk analysis, build-log inspection, maintainer lookup, and report generation into a single repeatable pipeline. What is usually scattered across spreadsheets, ad hoc scripts, and Slack threads becomes one structured workflow.

> From malicious package publication to team-by-team impact report, in a single pipeline.

## What You Get

- Org-wide repository sweep for confirmed malicious versions and semver-based exposure
- Build-log analysis to tell apart `npm install` compromise paths from safer `npm ci` flows
- Maintainer and team attribution for every affected repository
- Team dashboards, incident-response summaries, and reusable self-scan kits
- Public-facing docs, forensic evidence bundles, and local lab environments for validation

## When To Use It

- A malicious npm version was published and you need blast-radius analysis now
- Lockfiles alone are not trustworthy enough to answer what really ran
- You need one output for security leadership and another for engineering teams
- You want a reusable playbook instead of rebuilding the same incident scripts every time

---

## Why Build Logs, Not Lockfiles

The core of this attack is **evidence destruction**. When the malicious `postinstall` hook executes, it:

1. Downloads and runs a platform-specific RAT (Remote Access Trojan)
2. Deletes `setup.js` (the dropper)
3. Replaces the malicious `package.json` with a clean v4.2.0 stub

After `npm install` completes, a developer inspecting `node_modules` would see nothing wrong. With no filesystem traces left behind, **analyzing lockfiles or source trees after the fact cannot determine whether infection actually occurred.**

**Jenkins build logs, on the other hand, are immutable records of what commands ran at build time.** If a build executed `npm install` during the attack window (2026-03-31 00:21–03:51 UTC), that environment should be considered compromised.

In practice, lockfile-based analysis alone had clear limitations:

- **Docker builds overwriting lockfiles with older versions** — the lockfile no longer reflects the actual dependencies that were installed
- **Deployed artifacts not including lockfiles** — making it impossible to verify infection on production servers
- **Lockfiles in Bitbucket not matching the actual build** — the lockfile from the developer's machine or CI was never committed back to the repo

The question isn't "what does the code look like now" but **"what actually ran in the build environment at that time"** — and that record only exists in Jenkins build logs. This is why PoisonChain focuses on build log analysis.

> For detailed attack analysis, see:
> - [Hunt.io — Axios Supply Chain Attack: TA444/BlueNoroff](https://hunt.io/blog/axios-supply-chain-attack-ta444-bluenoroff)
> - [Endor Labs — npm axios Compromise](https://www.endorlabs.com/learn/npm-axios-compromise)
>
> The C2 server for this attack (`sfrclak.com` → Hostwinds AS54290) was hosted on an anonymous VPS accepting cryptocurrency payments. For detection rules and IP ranges of such providers, see [windshock/anonymous-vps](https://github.com/windshock/anonymous-vps).

---

## What Problem Does It Solve

In March 2026, `axios@1.14.1` and `plain-crypto-js@4.2.1` were published to npm as malicious versions. Via `postinstall` hooks, they exfiltrated npm tokens, GitHub PATs, SSH keys, and other credentials.

PoisonChain is built around the core questions an incident-response team has to answer:

| Question | What PoisonChain Does |
|----------|----------------------|
| How many repos are infected? | Full Bitbucket scan → detect malicious versions in lockfiles |
| Which repos could be re-infected on `npm install`? | Semver range analysis (can `^1.14.0` pull `1.14.1`?) |
| Who maintains each repo? | Extract recent committers + HR system integration (active/departed) |
| Which builds ran during the attack window? | Batch scan Jenkins instances, distinguish `npm install` vs `npm ci` |
| Need a per-team remediation report? | Auto-generate dashboards by team, repo, and risk level |

---

## Pipeline Flow

```
Malicious package published
        │
        ▼
┌─ canisterworm_analysis.py ──┐   Match IOCs against vuln DB
│  46 CanisterWorm campaign    │   → direct matches + IOC keyword search
│  packages + IOC keywords     │
└─────────────┬───────────────┘
              ▼
┌─ bitbucket_full_scan.py ────┐   Full Bitbucket repo scan
│  lockfile parsing + semver   │   → confirmed infected / semver risk
└─────────────┬───────────────┘
              ▼
┌─ fetch_committers.py ───────┐   Extract recent committers per repo
│  + check_employee_status.py │   → name, email, team, active/departed
└─────────────┬───────────────┘
              ▼
┌─ jenkins_scan.py ───────────┐   Batch scan Jenkins instances
│  cross-reference with attack │   → npm install detection + risk level
│  window builds               │
└─────────────┬───────────────┘
              ▼
┌─ report_axios_by_team.py ───┐   Per-team dashboard + IR reports
│  executive reporting + IR    │   → batch Markdown report generation
└─────────────────────────────┘
```

Run all at once:
```bash
./scripts/run_full_pipeline.sh --with-hr --with-lockfile
```

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/<your-org>/PoisonChain.git
cd PoisonChain

# 2. Configure environment
cp public/.env.example .env
# Edit .env and fill in XEIZE_API_KEY, etc.

# 3. Run pipeline
./scripts/run_full_pipeline.sh --help     # see options
./scripts/run_full_pipeline.sh            # default run
```

**Requirements:** Python 3.9+, `requests` library, API access to your analysis targets

> **Compatibility note:** This repository keeps the original `XEIZE_*` API naming and Bitbucket/Jenkins-oriented examples because they reflect the production workflow the toolkit was built from. If your environment uses GitHub/GitLab, GitHub Actions/CircleCI, or another scanner/provider, adapt the integration points and keep the pipeline design.

## Why It Matters

PoisonChain is opinionated about incident response: detection is not enough, and a raw package IOC list is not enough. Teams need evidence, ownership, and an execution path. This repo packages that operational layer so you can go from package compromise to remediation planning without inventing a new workflow under pressure.

---

## Scripts

| Script | Purpose | Input | Output |
|--------|---------|-------|--------|
| `canisterworm_analysis.py` | IOC matching for CanisterWorm campaign (46 packages) | Vuln scan API | Impact report |
| `bitbucket_full_scan.py` | Full repo lockfile scan + semver risk analysis | Bitbucket API | Per-repo infection/risk JSON |
| `canisterworm_lockfile_scan.py` | Fetch actual lockfiles from git for deep scan | Git PAT | Per-package match report |
| `fetch_committers.py` | Extract recent committers per repo | Bitbucket API | Committer info JSON |
| `check_employee_status.py` | Verify committer active/departed status | HR portal | Status annotations |
| `jenkins_scan.py` | Analyze build pipelines during attack window | Jenkins API | Per-job risk level JSON |
| `report_axios_by_team.py` | Generate per-team dashboards | All above outputs | Markdown reports |
| `preserve_evidence.py` | Archive malicious packages + SHA verification | npm/Datadog/GitHub | Forensic evidence bundle |
| `verify_repos.py` | Clean up deleted/excluded repos | Scan result JSON | Sanitized JSON |

---

## Local Lab Environment

`public/lab/` includes a Docker-based test environment. Verify script logic without real infrastructure.

```bash
cd public/lab/jenkins
docker compose up -d --build
# Jenkins: http://localhost:18080
```

11 pre-configured Jenkins jobs let you test `jenkins_scan.py` risk assessment logic:
- `axios-semver-risk` — `npm install` + semver risk → CRITICAL
- `axios-safe` — pinned safe version → LOW
- `no-axios-java` — Java build → not npm-related

Semver edge case test:
```bash
cd public/lab/caret-021-only
npm install && npm ls axios    # verify ^0.21.0 does NOT pull 0.30.x
```

---

## Outputs

- Repository-level JSON for confirmed and potential exposure
- Jenkins scan JSON with job-level risk scoring and partial-scan metadata
- Team-specific Markdown reports for engineering follow-up
- Email drafts and response material in local operating copies
- Public documentation and lab assets for reproducible validation

---

## Developer Self-Scan Kit

`public/dist/jenkins-scan-kit.zip` is a **standalone scan tool** you can distribute directly to dev teams. Requires only Python 3.9 — no external dependencies.

```
jenkins-scan-kit/
├── jenkins_scan.py              # scan script (single file)
├── config/jenkins-instances.json # target Jenkins instances
├── .env.example                 # env var template
├── reports/                     # output directory
└── README.md                    # 3-step guide
```

**Operational flow:**
1. Security team emails the zip + token provisioning instructions to team leads
2. Team lead enters their Jenkins URL and token in `.env`, runs `python3 jenkins_scan.py`
3. Reports back `risk_level: CRITICAL/HIGH` items from `reports/jenkins-scan-result.json`

Zero external dependencies — works in air-gapped environments.

---

## Forensic Evidence

`public/evidence/` preserves original malicious package tarballs and their hashes.

Samples are sourced from Datadog's public malicious package dataset ([DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset)). `preserve_evidence.py` automates download, hash verification, and metadata generation.

```
public/evidence/
├── axios@1.14.1/
│   ├── axios-1.14.1.tgz        # malicious package (Datadog dataset)
│   ├── metadata.json            # source, acquisition time, SHA256/SHA1
│   ├── sha256.txt
│   └── sha1.txt
└── plain-crypto-js@4.2.1/
    └── ...
```

Each `metadata.json` records the acquisition source (`source`), timestamp (`acquired_at`), and cryptographic hashes — verifiable against SANS-published indicators.

---

## Project Structure

```
PoisonChain/
├── scripts/          Analysis scripts (Python + Shell)
├── public/
│   ├── api-spec/     Vuln scanner API spec (OpenAPI 3.1)
│   ├── dist/         Distributable packages
│   ├── docs/         Jenkins security guide, GuardDog integration guide
│   ├── evidence/     Forensic evidence archive
│   ├── handoff/      API authentication summary
│   └── lab/          Docker-based test environment
├── internal/         ⛔ Internal only (reports, config, email drafts)
├── .env.example      Environment variable template
└── .env              ⛔ Secrets (not tracked by git)
```

---

## Documentation

- [`public/handoff/HANDOFF.md`](public/handoff/HANDOFF.md) — API authentication summary
- [`public/docs/analysis-of-axios-supply-chain-incident-based-on-maintainer-report.md`](public/docs/analysis-of-axios-supply-chain-incident-based-on-maintainer-report.md) — Maintainer post-mortem based analysis of the axios incident
- [`public/docs/axios-npm-supply-chain-attack-report.md`](public/docs/axios-npm-supply-chain-attack-report.md) — Deep technical analysis of payloads, RAT behavior, and IOCs
- [`public/docs/JENKINS-SECURITY-GUIDE.md`](public/docs/JENKINS-SECURITY-GUIDE.md) — Jenkins supply chain security guide
- [`public/docs/GUARDDOG-JENKINS-GUIDE.md`](public/docs/GUARDDOG-JENKINS-GUIDE.md) — GuardDog + Jenkins Shared Library integration
- [`public/lab/README.md`](public/lab/README.md) — Local lab environment

---

## License

MIT
