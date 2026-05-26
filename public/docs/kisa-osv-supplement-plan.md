# KISA / OSV Supplemental Malicious Package Index Plan

## Goal

Improve PoisonChain's malicious npm package single source of truth (SSOT) so it does not rely on Datadog samples alone. Datadog remains a high-value broad dataset, but incident advisories such as KISA, OSV/GHSA, JFrog, and vendor postmortems can contain package names or versions that are missing from, delayed in, or named differently from the Datadog sample tree.

The immediate driver is the KISA Supply Chain Diffusion Attack hunting guide comparison, where several KISA-listed package names were absent from the local `public/data/malicious-packages.json` even though related packages and campaigns are already tracked.

## Current State

`public/data/malicious-packages.json` is the SSOT consumed by scan and evidence workflows. `scripts/build_malicious_package_index.py` validates and refreshes the SSOT from the Datadog malicious-software-packages-dataset metadata tree. The script preserves manual campaign entries and auto-refreshes `datadog_auto` entries.

This is good for Datadog-covered packages, but it has three limitations:

1. **Datadog sample coverage is not a complete ground truth.** A missing package in Datadog should be treated as inconclusive, not benign.
2. **Secondary advisory names may differ from canonical npm package names.** Some KISA-style names appear to be aliases or summaries of canonical names used by OSV/GHSA/Datadog.
3. **Package-name-only imports create false positives.** For compromised legitimate packages, exact malicious versions should be required when available.

## Observed Gaps From KISA Comparison

Packages absent from the local SSOT at comparison time included:

```text
@emilgroup/changelog-sdk
@emilgroup/numbergenerator-sdk
@tanstack/create-router
@tanstack/directive-functions-plugin
@tanstack/react-cross-context
@tanstack/react-router-with-query
@tanstack/router-arktype-adapter
@tanstack/router-esbuild-plugin
@tanstack/router-rspack-plugin
@tanstack/router-valibot-adapter
@tanstack/router-webpack-plugin
@tanstack/router-zod-adapter
@tanstack/server-functions-plugin
@tanstack/start
@tanstack/start-api-routes
@tanstack/start-client
@tanstack/start-config
@tanstack/start-plugin
@tanstack/start-server
@tanstack/start-server-functions-client
@tanstack/start-server-functions-fetcher
@tanstack/start-server-functions-handler
@tanstack/start-server-functions-ssr
@tanstack/start-vite-plugin
react-leaflet-heatmap-layer
```

These names should not all be blindly appended. Some may be aliases, outdated summary names, meta packages, or package names that require vendor/advisory confirmation.

## Source Priority

Use this priority order when enriching the SSOT:

1. **OSV/GHSA machine-readable advisories**
   - Best for package names and exact affected versions.
   - Example: `GHSA-g7cv-rxg3-hmpx` for TanStack.
   - API: `https://api.osv.dev/v1/vulns/<ID>`.

2. **Datadog malicious-software-packages-dataset**
   - Best for broad malicious package sample coverage and discovery dates.
   - Continue using it as the main automated source.

3. **Vendor/security postmortems**
   - Best for incident context, root cause, remediation, and clean-package clarifications.
   - Example: TanStack postmortem for the May 2026 compromise.

4. **JFrog / GitLab / Snyk advisories**
   - Useful for CanisterWorm package/version validation and individual package checks.
   - Prefer machine-readable or clearly tabulated exact version data.

5. **KISA hunting guide / internal report summaries**
   - Useful as a hunting checklist and gap-discovery source.
   - Do not automatically import names when exact versions or canonical npm names are unclear.

## Implementation Added In This PR

### 1. Supplemental source registry

Added:

```text
public/data/supplemental-malicious-package-sources.json
```

This file tracks:

- OSV advisory IDs to import.
- Campaign metadata for supplemental advisory-backed imports.
- Manual-review aliases where secondary reports and canonical npm names may differ.
- Human-review sources such as JFrog and TanStack postmortem references.

### 2. OSV supplement importer

Added:

```text
scripts/supplement_malicious_package_index.py
```

The importer:

- Loads `public/data/supplemental-malicious-package-sources.json`.
- Calls OSV API directly without an API key.
- Extracts canonical npm package names from `affected[].package.name`.
- Imports only affected rows with exact `versions` to avoid package-name-only false positives.
- Merges versions into existing SSOT entries rather than replacing them.
- Adds `osv_advisories` and `references` fields to entries for traceability.
- Runs dry by default; `--write` is required to update the SSOT.

Example:

```bash
python3 scripts/supplement_malicious_package_index.py --dry-run
python3 scripts/supplement_malicious_package_index.py --advisory GHSA-g7cv-rxg3-hmpx --write
python3 scripts/build_malicious_package_index.py --validate
```

## Handling github.com/google/osv.dev

Do not scrape the `google/osv.dev` GitHub repository as the primary vulnerability data source.

Use it for:

- API documentation and implementation reference.
- Understanding schema behavior.
- Local development reference.

Use these for actual data:

- `https://api.osv.dev/v1/vulns/<ID>` for advisory-by-ID imports.
- OSV bulk exports / dumps when a full mirror is required.

Reason: the GitHub repository contains OSV service source code and supporting assets, not the most convenient or stable interface for vulnerability records. OSV API and dumps are the intended data products.

## Merge Rules

For `compromised_legitimate` packages:

- Require exact malicious versions when importing automatically.
- Do not mark every version of the package as malicious.
- Merge incoming versions with existing `malicious_versions`.
- Preserve existing campaign metadata unless the new source is the only source for a package.

For `malicious_intent` packages:

- Package-name-level detection may be acceptable, but still store versions when available.

For aliases or uncertain names:

- Put them in `manual_review_aliases`.
- Do not add them to `packages` until a machine-readable or strongly documented source confirms canonical npm name and affected version.

## Recommended Follow-Up Work

1. Run the OSV supplement importer for `GHSA-g7cv-rxg3-hmpx` and inspect the diff.
2. Compare the resulting TanStack entries against the KISA gap list.
3. Confirm `react-leaflet-heatmap-layer@2.0.1` against JFrog/GitLab/Snyk or Datadog manifest and update the SSOT if the local entry is still missing.
4. Review `@emilgroup/changelog-sdk` and `@emilgroup/numbergenerator-sdk` aliases against JFrog and Datadog canonical package names before importing.
5. Add CI automation after the dry-run output is reviewed:
   - `python3 scripts/build_malicious_package_index.py --refresh`
   - `python3 scripts/supplement_malicious_package_index.py --write`
   - `python3 scripts/build_malicious_package_index.py --validate`

## Acceptance Criteria

- `scripts/supplement_malicious_package_index.py --dry-run` can fetch configured OSV advisories and print a summary.
- `--write` updates only the SSOT and preserves existing manual campaign entries.
- No package-name-only TanStack entries are imported when exact OSV versions are missing.
- `build_malicious_package_index.py --validate` passes after supplement import.
- Manual-review aliases remain separate from automatic package entries.
