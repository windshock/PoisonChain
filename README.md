# PoisonChain 🔗☠️

[한국어](README.ko.md)

**A malicious npm package just dropped. How many repos in your org are affected, who maintains them, and which builds ran during the attack window?**

PoisonChain **automatically maps the blast radius** of an npm supply chain attack across your entire organization. It scans thousands of repositories to identify affected projects, their maintainers, and compromised build pipelines — then generates per-team incident response dashboards.

> What would take weeks of manual analysis, **done in 2 hours.**

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

Questions a security team must answer:

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

> **Note:** The scripts in this repo were built against a specific internal stack (Bitbucket, Jenkins, a proprietary vulnerability scanner API). Your organization will likely use different systems — GitHub/GitLab, GitHub Actions/CircleCI, Snyk/Dependabot, Okta/AD, etc. The value here is the **methodology and pipeline logic**, not the specific API calls. Fork and adapt the integration points to your own environment.

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
- [`public/docs/JENKINS-SECURITY-GUIDE.md`](public/docs/JENKINS-SECURITY-GUIDE.md) — Jenkins supply chain security guide
- [`public/docs/GUARDDOG-JENKINS-GUIDE.md`](public/docs/GUARDDOG-JENKINS-GUIDE.md) — GuardDog + Jenkins Shared Library integration
- [`public/lab/README.md`](public/lab/README.md) — Local lab environment

---

## License

MIT
