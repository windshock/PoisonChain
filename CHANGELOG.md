# Changelog

All notable changes to PoisonChain are documented here.
Versioning follows [Semantic Versioning](https://semver.org/):
- **MAJOR** — breaking schema changes or fundamental architecture shifts
- **MINOR** — new ecosystems, new data sources, new script features
- **PATCH** — data refreshes, bug fixes, minor improvements

---

## [2.0.0] — 2026-06-02 `aa5b84b`

### Data
- **SSOT: 15,587 → 28,188 packages (+12,601)**
  - npm: 13,217 → 15,902 (+2,685) via OSV incremental scan since 2025-12-01
  - PyPI: 1,577 → 11,483 (+9,906) via OSV full scan (all.zip, 11,254 advisories)
  - NuGet: 773 → 781 (+8) via Socket-only manual entries
  - Go: 18 → 20 (+2) via Socket-only manual entries
  - Maven: 2 (unchanged)
- Added `data_version`, `total_count`, `ecosystem_counts` fields to SSOT JSON

### Features
- `merge_manual_packages()` — permanent storage for OSV-unregistered packages (Socket/JFrog reports)
- `manual_packages` section in `supplemental-malicious-package-sources.json`
  - 13 packages: Go×2, NuGet×8, npm×3
  - 6 campaigns: socket_research_2026, bufferzonecorp_may_2026, trapdoor_may_2026, contagious_interview_2026, ir_chinese_ui_2026, sicoob_sdk_2026

### Fixes
- `--ecosystems` flag case-insensitive matching (`pypi` → `PyPI`, `nuget` → `NuGet`, etc.)
- Per-ecosystem OSV timestamps prevent full re-scans after targeted incremental runs

---

## [1.0.0] — 2026-06-02 `017321d`

### Data
- **SSOT: ~13,174 → 15,587 packages**
  - Maven: 0 → 2 (first Maven malicious packages)
  - Go: 0 → 18 (first Go malicious packages via OSSF)
  - NuGet: 0 → 773 (first NuGet malicious packages via OSV bulk)
  - PyPI: 0 → 1,577 (first PyPI packages via Datadog + OSV)

### Features
- Multi-ecosystem SSOT: npm, PyPI, Maven, Go, NuGet (crates.io planned)
- Per-ecosystem OSV refresh timestamps (`osv_malicious_by_eco`)
- OSV GCS bulk scan extended to all supported ecosystems

---

## [0.5.0] — 2026-06-02 `f12a8c5`

### Features
- `--refresh-osv` flag: auto-discover new npm malicious advisories from OSV GCS bulk bundle
- `--full` flag: download and process entire OSV ecosystem bundle (not incremental)
- Nexus proxy scan extended to PyPI, Maven, crates.io, Go, NuGet

---

## [0.4.0] — 2026-05-27 `806d858`

### Features
- `campaign.kind` discriminator: `'incident'` vs `'catalog'` (IOC matchers skip catalogs)
- 2-track pipeline docs: generic SSOT-driven vs campaign-specific analyzers
- zizmor CI security checks; pinned action SHAs
- Direct BITBUCKET_PAT helper (replaces removed XEIZE endpoint)

---

## [0.3.0] — 2026-05-26 `b83b899`

### Features
- OSV/KISA supplemental advisory enrichment (`supplement_malicious_package_index.py`)
- `confidence` tier: `confirmed` (OSV/GHSA/Datadog + takedown) vs `suspected` (KISA-only)
- `datadog_added` + `version_dates` fields for all Datadog-sourced packages
- SSOT-driven scan scripts; KISA audit data integration

---

## [0.2.0] — 2026-04-14 `bae332c`

### Features
- Public release documentation and polish
- PDF slide download links, YouTube video embed
- Sanitized Nexus scan demo

---

## [0.1.0] — 2026-04-06 `a7a01b9`

### Initial Release
- CanisterWorm npm supply chain attack blast radius analyzer
- Malware payload evidence index
- Initial SSOT for npm malicious packages (CanisterWorm campaign)
- Bitbucket and Jenkins scan scripts
