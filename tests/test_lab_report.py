"""Offline tests for the strict lab-report validator."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from it_grc.lab_report import (
    SCENARIOS,
    InvalidEvidence,
    canonical_record,
    import_lab,
    read_json_artifact,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures/lab/demo-report-2026-10-13.json"
REVISION = "ab" * 20


class LabReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw: dict[str, Any] = {
            "backend": "lima-kubernetes-containerd",
            "timestamp": datetime.now(UTC).isoformat(),
            "passed": True,
            "results": [{"scenario": n, "passed": True} for n in range(1, 19)],
        }

    def imported(self, raw: dict[str, Any]) -> dict[str, Any]:
        return import_lab(raw, json.dumps(raw).encode())

    def test_import_preserves_capture_time_and_selects_only_safe_fields(self) -> None:
        self.raw["private_payload"] = "never retain this"
        result = self.imported(self.raw)
        self.assertEqual(result["execution"], "saved")
        self.assertEqual(result["origin"], "executed_lab_report")
        self.assertEqual(result["captured_at"], self.raw["timestamp"])
        self.assertNotIn("private_payload", result)
        self.assertNotIn("never retain", json.dumps(result))
        self.assertEqual([row["id"] for row in result["scenarios"]], list(SCENARIOS))

    def test_incomplete_duplicate_false_summary_and_future_times_are_rejected(self) -> None:
        for mutate in (
            lambda r: r["results"].pop(),
            lambda r: r["results"].append({"scenario": 19, "passed": True}),
            lambda r: r["results"][1].update(scenario=1),
            lambda r: r["results"][1].update(scenario=True),
            lambda r: r["results"][0].update(passed=False),
            lambda r: r["results"][0].update(passed="true"),
            lambda r: r.update(timestamp=(datetime.now(UTC) + timedelta(days=1)).isoformat()),
            lambda r: r.update(timestamp="2026-10-06T10:00:00"),
            lambda r: r.update(backend="docker"),
        ):
            raw = copy.deepcopy(self.raw)
            mutate(raw)
            with self.assertRaises(InvalidEvidence):
                self.imported(raw)

    def test_untrusted_revision_metadata_cannot_enter_the_import(self) -> None:
        for revisions in (
            {"mcp-svid-auth": {"revision": "not-a-commit", "dirty": False}},
            {"unknown-producer": {"revision": REVISION, "dirty": False}},
            {"mcp-svid-auth": {"revision": REVISION, "dirty": "no"}},
            {"mcp-svid-auth": {"revision": REVISION, "dirty": False, "note": "x"}},
            [],
        ):
            self.raw["producer_revisions"] = revisions
            with self.subTest(revisions=revisions), self.assertRaises(InvalidEvidence):
                self.imported(self.raw)
        self.raw["producer_revisions"] = {"mcp-svid-auth": {"revision": REVISION, "dirty": True}}
        result = self.imported(self.raw)
        self.assertEqual(result["producer_revisions"]["mcp-svid-auth"]["revision"], REVISION)

    def test_digest_format_rejects_nonfinite_unknown_values(self) -> None:
        self.raw["unknown"] = float("nan")
        with self.assertRaisesRegex(InvalidEvidence, "invalid_json_record"):
            self.imported(self.raw)

    def test_failed_scenario_is_retained_as_a_failed_check(self) -> None:
        self.raw["passed"] = False
        self.raw["results"][0]["passed"] = False
        result = self.imported(self.raw)
        self.assertFalse(result["passed"])
        self.assertFalse(result["scenarios"][0]["passed"])

    def test_record_digest_ignores_layout_and_artifact_digest_keeps_the_bytes(self) -> None:
        compact = json.dumps(self.raw).encode()
        reordered = json.dumps(dict(reversed(list(self.raw.items()))), indent=2).encode()
        first, second = import_lab(self.raw, compact), import_lab(self.raw, reordered)
        self.assertEqual(first["record_sha256"], second["record_sha256"])
        self.assertEqual(
            first["record_sha256"], hashlib.sha256(canonical_record(self.raw)).hexdigest()
        )
        self.assertEqual(first["artifact_sha256"], hashlib.sha256(compact).hexdigest())
        self.assertNotEqual(first["artifact_sha256"], second["artifact_sha256"])
        self.assertEqual(first["artifact_digest_kind"], "raw_file_bytes")
        self.assertEqual(first["record_digest_format"], "json-sort-keys-compact-ascii-v1")
        changed = copy.deepcopy(self.raw)
        changed["results"][0]["passed"] = False
        changed["passed"] = False
        self.assertNotEqual(first["record_sha256"], self.imported(changed)["record_sha256"])

    def test_duplicate_keys_oversized_files_and_non_objects_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "report.json"
            for content, code in (
                # A duplicate key is refused while parsing, so it reports invalid_json.
                ('{"a":1,"a":2}', "invalid_json"),
                ("[1, 2]", "invalid_document"),
                ("{not json", "invalid_json"),
            ):
                file.write_text(content)
                with self.subTest(code=code), self.assertRaisesRegex(InvalidEvidence, code):
                    read_json_artifact(file)
            file.write_text(json.dumps({"padding": "x" * 100}))
            with self.assertRaisesRegex(InvalidEvidence, "evidence_too_large"):
                read_json_artifact(file, max_bytes=64)

    def test_the_retained_fixture_passes_with_its_recorded_digests(self) -> None:
        raw, artifact = read_json_artifact(FIXTURE)
        result = import_lab(raw, artifact)
        self.assertTrue(result["passed"])
        self.assertEqual(result["captured_at"], "2026-10-13T07:51:16.369462+00:00")
        self.assertEqual(result["producer_revisions"], {})
        self.assertTrue(result["artifact_sha256"].startswith("733de041"))
        self.assertTrue(result["record_sha256"].startswith("de28b5bd"))


if __name__ == "__main__":
    unittest.main()
