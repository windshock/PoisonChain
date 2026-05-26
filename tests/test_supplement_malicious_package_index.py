"""Tests for scripts/supplement_malicious_package_index.py category branching.

These tests pin the trust-tiering policy:
- compromised_legitimate requires exact versions; range-only OSV rows must
  be dropped (otherwise we would block every clean release of a hijacked
  legitimate package).
- malicious_intent is detected by package name; range-only OSV rows must
  still produce an SSOT entry, since the name itself is the signal.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from supplement_malicious_package_index import (  # noqa: E402
    merge_kisa_listed,
    merge_osv_advisory,
)


def _osv_range_only(name: str) -> dict:
    return {
        "id": "GHSA-test-0000-0000",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": name},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ],
        "references": [],
    }


def _osv_with_versions(name: str, versions: list[str]) -> dict:
    return {
        "id": "GHSA-test-1111-1111",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": name},
                "versions": versions,
            }
        ],
        "references": [],
    }


class MergeOsvAdvisoryTests(unittest.TestCase):
    def test_compromised_legitimate_drops_range_only_row(self) -> None:
        index: dict = {"packages": []}
        cfg = {
            "id": "GHSA-test-0000-0000",
            "campaign": "tanstack_may_2026",
            "category": "compromised_legitimate",
        }
        added, updated, unchanged = merge_osv_advisory(
            index, cfg, _osv_range_only("@tanstack/router")
        )
        self.assertEqual((added, updated, unchanged), (0, 0, 1))
        self.assertEqual(index["packages"], [])

    def test_malicious_intent_keeps_range_only_row_by_name(self) -> None:
        index: dict = {"packages": []}
        cfg = {
            "id": "GHSA-test-0000-0000",
            "campaign": "external_advisory_supplement",
            "category": "malicious_intent",
        }
        added, updated, unchanged = merge_osv_advisory(
            index, cfg, _osv_range_only("plain-crypto-js")
        )
        self.assertEqual((added, updated, unchanged), (1, 0, 0))
        self.assertEqual(len(index["packages"]), 1)
        entry = index["packages"][0]
        self.assertEqual(entry["name"], "plain-crypto-js")
        self.assertEqual(entry["category"], "malicious_intent")
        self.assertEqual(entry["malicious_versions"], [])
        self.assertEqual(entry["osv_advisories"], ["GHSA-test-0000-0000"])

    def test_compromised_legitimate_imports_exact_versions(self) -> None:
        index: dict = {"packages": []}
        cfg = {
            "id": "GHSA-test-1111-1111",
            "campaign": "tanstack_may_2026",
            "category": "compromised_legitimate",
        }
        added, updated, unchanged = merge_osv_advisory(
            index, cfg, _osv_with_versions("@tanstack/router", ["1.132.1"])
        )
        self.assertEqual((added, updated, unchanged), (1, 0, 0))
        entry = index["packages"][0]
        self.assertEqual(entry["malicious_versions"], ["1.132.1"])
        self.assertEqual(entry["confidence"], "confirmed")


def _kisa_cfg() -> dict:
    return {
        "campaign": "tanstack_may_2026",
        "default_category": "compromised_legitimate",
        "upstream_carveouts": [{"package": "@tanstack/start", "reason": "postmortem"}],
        "packages": [
            {"name": "@tanstack/start", "npm_status": "exists", "confidence": "suspected"},
            {"name": "@tanstack/start-server", "npm_status": "exists", "confidence": "suspected"},
            {"name": "@tanstack/router-esbuild-plugin", "npm_status": "not_found", "confidence": "confirmed"},
        ],
        "references": ["https://tanstack.com/blog/npm-supply-chain-compromise-postmortem"],
    }


class MergeKisaListedTests(unittest.TestCase):
    def test_carveout_excludes_named_package(self) -> None:
        index: dict = {"packages": []}
        added, _, _ = merge_kisa_listed(index, _kisa_cfg())
        names = {p["name"] for p in index["packages"]}
        self.assertNotIn("@tanstack/start", names)
        self.assertEqual(added, 2)

    def test_npm_404_entries_tagged_confirmed(self) -> None:
        index: dict = {"packages": []}
        merge_kisa_listed(index, _kisa_cfg())
        by_name = {p["name"]: p for p in index["packages"]}
        not_found = by_name["@tanstack/router-esbuild-plugin"]
        self.assertEqual(not_found["confidence"], "confirmed")
        self.assertEqual(not_found["npm_status"], "not_found")
        self.assertEqual(not_found["source"], "kisa_listed")

    def test_npm_exists_entries_tagged_suspected(self) -> None:
        index: dict = {"packages": []}
        merge_kisa_listed(index, _kisa_cfg())
        by_name = {p["name"]: p for p in index["packages"]}
        existing = by_name["@tanstack/start-server"]
        self.assertEqual(existing["confidence"], "suspected")
        self.assertEqual(existing["npm_status"], "exists")
        self.assertEqual(existing["malicious_versions"], [])

    def test_existing_confirmed_entry_is_not_demoted(self) -> None:
        # Simulate the post-OSV state: an entry was just imported as confirmed.
        # Re-running the KISA pass must not lower its confidence to suspected.
        existing_entry = {
            "name": "@tanstack/start-server",
            "ecosystem": "npm",
            "category": "compromised_legitimate",
            "campaign": "tanstack_may_2026",
            "source": "osv_advisory",
            "confidence": "confirmed",
            "malicious_versions": ["1.166.99"],
        }
        index: dict = {"packages": [existing_entry]}
        merge_kisa_listed(index, _kisa_cfg())
        self.assertEqual(existing_entry["confidence"], "confirmed")
        self.assertEqual(existing_entry["malicious_versions"], ["1.166.99"])


if __name__ == "__main__":
    unittest.main()
