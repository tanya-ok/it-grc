"""Offline tests for the mapping, the push and verify against the in-memory CISO Assistant
stand-in on loopback HTTPS. No VM and no external network."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from grc_fake import NODE_PREFIX, OPENSSL
from test_grc_ops import OperationsTestCase

from it_grc import grc_ledger as gl
from it_grc import grc_mapping as gm
from it_grc import grc_ops as ops
from it_grc import grc_push as gp
from it_grc.grc_client import GrcLookupError

ROOT = Path(__file__).resolve().parent.parent
MAPPING = ROOT / "mappings/hipaa-800-66r2.json"
REPORT = ROOT / "fixtures/lab/demo-report-2026-10-13.json"
AUDIT_ID = "6f7c1d2e-0a3b-4c5d-8e9f-0123456789ab"


def raw_mapping() -> dict[str, Any]:
    value: dict[str, Any] = json.loads(MAPPING.read_text())
    return value


def library_nodes() -> list[dict[str, Any]]:
    """Section and assessable nodes named as in the mapping, like the live library."""
    mapping = gm.load_mapping(MAPPING)
    sections = sorted({target.section for target in mapping.targets})
    rows: list[dict[str, Any]] = [
        {"urn": NODE_PREFIX + section, "name": "", "assessable": False, "parent_urn": None}
        for section in sections
    ]
    rows += [
        {
            "urn": target.urn,
            "name": target.name,
            "assessable": True,
            "parent_urn": NODE_PREFIX + target.section,
        }
        for target in mapping.targets
    ]
    # An assessable node the mapping does not touch.
    rows.append(
        {
            "urn": NODE_PREFIX + "node4",
            "name": "1. Identify",
            "assessable": True,
            "parent_urn": None,
        }
    )
    return rows


class GuardTests(unittest.TestCase):
    def test_guard_refuses_writes_above_the_ceiling_or_outside_the_allowlist(self) -> None:
        assessment = f"/requirement-assessments/{AUDIT_ID}/"
        refused = [
            ("PATCH", assessment, {"result": "compliant"}),
            ("PATCH", assessment, {"result": "not_applicable"}),
            ("PATCH", assessment, {"status": "done"}),
            ("PATCH", assessment, {"status": "in_progress"}),
            ("PATCH", assessment, {"review_state": "accepted"}),
            ("PATCH", assessment, {"is_locked": True}),
            ("PATCH", f"/compliance-assessments/{AUDIT_ID}/", {"is_locked": True}),
            ("PATCH", f"/compliance-assessments/{AUDIT_ID}/", {"status": "done"}),
            ("POST", "/compliance-assessments/", {"name": "x", "status": "done"}),
            ("POST", "/evidences/", {"name": "x", "status": "approved"}),
            ("PATCH", f"/evidences/{AUDIT_ID}/", {"status": "approved"}),
            ("POST", "/applied-controls/", {"name": "x", "status": "active"}),
            ("DELETE", f"/compliance-assessments/{AUDIT_ID}/", {}),
            ("DELETE", f"/evidences/{AUDIT_ID}/", {}),
        ]
        for method, path, body in refused:
            with self.subTest(method=method, path=path), self.assertRaises(gm.CeilingError):
                gp.guard(method, path, body)
        gp.guard("PATCH", assessment, {"result": "partially_compliant", "status": "in_review"})
        gp.guard("POST", "/compliance-assessments/", {"name": "x", "status": "in_progress"})


@unittest.skipUnless(OPENSSL, "openssl is required to create a test CA")
class PushTestCase(OperationsTestCase):
    def nodes(self) -> list[dict[str, Any]] | None:
        return library_nodes()

    def setUp(self) -> None:
        super().setUp()
        self.settings = ops.Settings(
            data=self.data,
            origin=self.server.origin(),
            options=self.settings.options,
            report=REPORT,
            mapping=MAPPING,
        )
        self.run_op(ops.bootstrap)
        self.mapping = gm.load_mapping(MAPPING)
        self.plan = gm.build_plan(self.mapping, gm.load_report(REPORT))

    def with_settings(self, **changes: Any) -> None:
        values = {
            "data": self.data,
            "origin": self.settings.origin,
            "options": self.settings.options,
            "report": self.settings.report,
            "mapping": self.settings.mapping,
            "dry_run": False,
        }
        values.update(changes)
        self.settings = ops.Settings(**values)

    def assessment(self, suffix: str) -> dict[str, Any]:
        node = next(n for n in self.fake.nodes if n["urn"] == NODE_PREFIX + suffix)
        return next(a for a in self.fake.assessments.values() if a["requirement"] == node["id"])

    def evidence(self, ref_id: str) -> dict[str, Any]:
        return next(e for e in self.fake.evidences.values() if e["name"].startswith(ref_id + " "))

    def control(self) -> dict[str, Any]:
        return next(iter(self.fake.controls.values()))

    def revisions(self, ref_id: str) -> list[dict[str, Any]]:
        evidence = self.evidence(ref_id)["id"]
        rows = [r for r in self.fake.revisions.values() if r["evidence"] == evidence]
        return sorted(rows, key=lambda row: row["version"])

    def changed_report(self) -> Path:
        report = json.loads(REPORT.read_text())
        report["timestamp"] = "2026-10-13T09:00:00+00:00"
        path = self.data.parent / "report-2.json"
        path.write_text(json.dumps(report, indent=2))
        return path


class PushTests(PushTestCase):
    def test_push_creates_everything_once_and_a_second_push_changes_nothing(self) -> None:
        changes = self.run_op(gp.push)
        self.assertEqual(len(self.fake.audits), 1)
        audit = next(iter(self.fake.audits.values()))
        self.assertEqual((audit["ref_id"], audit["status"]), ("ITGRC-800-66R2", "in_progress"))
        self.assertFalse(audit["is_locked"])
        self.assertEqual(len(self.fake.evidences), 9)
        for item in self.plan.extracts:
            revisions = self.revisions(item.group.ref_id)
            self.assertEqual(len(revisions), 1)
            self.assertEqual(revisions[0]["content"], item.content)
            self.assertEqual(revisions[0]["attachment_hash"], item.sha256)
        control = next(iter(self.fake.controls.values()))
        self.assertEqual(control["ref_id"], "ITGRC-AC-KEY-ROTATION")
        self.assertEqual(control["status"], "--")
        self.assertEqual(control["evidences"], [self.evidence("ITGRC-EV-KEY-ROTATION")["id"]])

        node211 = self.assessment("node211")
        self.assertEqual(
            (node211["result"], node211["status"], node211["extended_result"]),
            ("partially_compliant", "in_review", "observation_sensitive_point"),
        )
        self.assertEqual(
            set(node211["evidences"]),
            {self.evidence(r)["id"] for r in ("ITGRC-EV-ACCESS", "ITGRC-EV-IDENTITY-LIMITS")},
        )
        node258 = self.assessment("node258")
        self.assertEqual(node258["applied_controls"], [control["id"]])
        self.assertEqual(len(node258["evidences"]), 4)
        gap = self.assessment("node321")
        self.assertEqual((gap["result"], gap["status"]), ("not_assessed", "to_do"))
        self.assertTrue(gap["observation"].startswith("not_verified: "))
        untouched = self.assessment("node4")
        self.assertEqual((untouched["result"], untouched["observation"]), ("not_assessed", ""))

        # The ceiling holds everywhere, nothing is approved, locked or deleted.
        for row in self.fake.assessments.values():
            self.assertNotIn(row["result"], {"compliant", "not_applicable"})
            self.assertNotIn(row["status"], {"done", "in_progress"})
        self.assertTrue(all(e["status"] == "in_review" for e in self.fake.evidences.values()))
        self.assertFalse(any(method in {"DELETE", "PUT"} for method, _ in self.fake.writes))
        for name in (gl.LEDGER_FILE, gl.CHECKPOINT_FILE):
            self.assertEqual((self.data / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(changes), 1 + 9 + 9 + 1 + 117)

        writes = len(self.fake.writes)
        self.assertEqual(self.run_op(gp.push), [])
        self.assertEqual(self.fake.writes[writes:], [])
        self.assertIn("Push complete: no changes", self.output.getvalue())
        self.assert_quiet()

    def test_dry_run_writes_nothing(self) -> None:
        self.with_settings(dry_run=True)
        writes = len(self.fake.writes)
        changes = self.run_op(gp.push)
        self.assertEqual(len(changes), 1 + 9 + 9 + 1 + 117)
        self.assertEqual(self.fake.writes[writes:], [])
        self.assertEqual((self.fake.audits, self.fake.evidences), ({}, {}))
        self.assertFalse((self.data / gl.LEDGER_FILE).exists())
        self.assertFalse((self.data / gl.CHECKPOINT_FILE).exists())
        printed = self.output.getvalue()
        self.assertIn("Would create audit ITGRC-800-66R2", printed)
        self.assertIn("Dry run: 137 planned change(s); nothing was written", printed)
        self.assert_quiet()
        # After a push, a dry run plans nothing.
        self.with_settings(dry_run=False)
        self.run_op(gp.push)
        self.with_settings(dry_run=True)
        self.assertEqual(self.run_op(gp.push), [])

    def test_a_changed_report_adds_revisions_only(self) -> None:
        self.run_op(gp.push)
        writes = len(self.fake.writes)
        self.with_settings(report=self.changed_report())
        changes = self.run_op(gp.push)
        self.assertEqual(len(changes), 9)
        self.assertEqual(self.fake.writes[writes:], [("POST", "/api/evidence-revisions/")] * 9)
        changed = gm.build_plan(self.mapping, gm.load_report(self.changed_report()))
        for old, new in zip(self.plan.extracts, changed.extracts, strict=True):
            revisions = self.revisions(old.group.ref_id)
            self.assertEqual([r["version"] for r in revisions], [1, 2])
            self.assertEqual(revisions[0]["attachment_hash"], old.sha256)
            self.assertEqual(revisions[1]["attachment_hash"], new.sha256)
            self.assertNotEqual(old.sha256, new.sha256)
        self.assertEqual(self.run_op(gp.push), [])

    def test_a_stored_hash_that_differs_from_the_upload_is_detected(self) -> None:
        self.fake.corrupt_hashes = True
        with self.assertRaisesRegex(ops.OpsError, "differs from the local sha256"):
            self.run_op(gp.push)
        self.assertEqual(self.assessment("node211")["result"], "not_assessed")

    def test_human_decisions_are_kept(self) -> None:
        self.run_op(gp.push)
        self.assessment("node211").update(result="compliant", status="done")
        self.assessment("node57").update(status="in_progress")
        writes = len(self.fake.writes)
        self.assertEqual(self.run_op(gp.push), [])
        self.assertEqual(self.fake.writes[writes:], [])
        printed = self.output.getvalue()
        self.assertIn(f"HELD {NODE_PREFIX}node211: result compliant", printed)
        self.assertIn(f"HELD {NODE_PREFIX}node57: status in_progress", printed)
        self.assertIn("2 requirement(s) held by human decisions", printed)
        self.assertEqual(self.assessment("node211")["result"], "compliant")


class WrongTargetTests(PushTestCase):
    def test_an_audit_with_the_ref_id_in_another_perimeter_is_refused(self) -> None:
        domain = next(f["id"] for f in self.fake.folders.values() if f["name"] == ops.DOMAIN)
        self.fake.perimeters["p2"] = {"id": "p2", "name": "Other", "ref_id": "X", "folder": domain}
        self.fake.audits["a2"] = {
            "id": "a2",
            "name": "Other",
            "ref_id": "ITGRC-800-66R2",
            "folder": domain,
            "perimeter": "p2",
            "framework": self.fake.frameworks[0]["id"],
            "status": "in_progress",
            "is_locked": False,
        }
        writes = len(self.fake.writes)
        with self.assertRaisesRegex(ops.OpsError, "outside the lab perimeter"):
            self.run_op(gp.push)
        self.assertEqual(self.fake.writes[writes:], [])

    def test_ignored_filters_stop_before_any_write(self) -> None:
        self.fake.ignored_filters.add(("/api/requirement-nodes/", "urn"))
        writes = len(self.fake.writes)
        with self.assertRaises(GrcLookupError):
            self.run_op(gp.push)
        self.assertEqual(self.fake.writes[writes:], [])
        self.fake.ignored_filters.clear()
        self.run_op(gp.push)
        self.fake.ignored_filters.add(("/api/requirement-assessments/", "requirement__urn"))
        self.assessment("node211")["observation"] = "edited"
        writes = len(self.fake.writes)
        with self.assertRaises(GrcLookupError):
            self.run_op(gp.push)
        self.assertEqual(self.fake.writes[writes:], [])

    def test_a_changed_library_node_or_locked_audit_is_refused(self) -> None:
        node = next(n for n in self.fake.nodes if n["urn"] == NODE_PREFIX + "node258")
        name, node["name"] = node["name"], "Renamed upstream"
        with self.assertRaisesRegex(ops.OpsError, "no longer matches the mapping"):
            self.run_op(gp.push)
        self.assertEqual(self.fake.audits, {})
        node["name"] = name
        self.run_op(gp.push)
        next(iter(self.fake.audits.values()))["is_locked"] = True
        self.assessment("node211")["observation"] = "edited"
        writes = len(self.fake.writes)
        with self.assertRaisesRegex(ops.OpsError, "locked"):
            self.run_op(gp.push)
        self.assertEqual(self.fake.writes[writes:], [])

    def test_a_token_with_a_wider_role_is_refused(self) -> None:
        manager = [g["id"] for g in self.fake.groups.values() if g["name"].endswith("manager")]
        self.bridge()["groups"] += manager
        with self.assertRaises(ops.OpsError):
            self.run_op(gp.push)
        self.assertEqual(self.fake.audits, {})


class VerifyTests(PushTestCase):
    def test_verify_is_clean_after_a_push(self) -> None:
        self.run_op(gp.push)
        self.assertEqual(self.run_op(gp.verify), [])
        printed = self.output.getvalue()
        self.assertIn("PASS verify", printed)
        self.assertIn("partially_compliant=20", printed)
        self.assertIn("Evidence coverage: covered=20", printed)
        self.assert_quiet()

    def test_verify_without_a_push_record_is_refused(self) -> None:
        with self.assertRaisesRegex(ops.OpsError, "run `it-grc push` first"):
            self.run_op(gp.verify)

    def test_verify_reports_drift(self) -> None:
        self.run_op(gp.push)
        cases: list[tuple[str, Any]] = [
            ("node211", lambda: self.assessment("node211").update(result="non_compliant")),
            ("node321", lambda: self.assessment("node321").update(observation="")),
            ("link(s)", lambda: self.assessment("node258").update(evidences=[])),
            ("hash", lambda: self.revisions("ITGRC-EV-ACCESS")[0].update(attachment_hash="1" * 64)),
            ("lost an evidence link", lambda: self.control().update(evidences=[])),
        ]
        for needle, tamper in cases:
            saved = copy.deepcopy((self.fake.assessments, self.fake.revisions, self.fake.controls))
            start = len(self.output.getvalue())
            tamper()
            with self.subTest(needle=needle), self.assertRaises(gp.DriftError):
                self.run_op(gp.verify)
            self.assertIn(needle, self.output.getvalue()[start:])
            self.fake.assessments, self.fake.revisions, self.fake.controls = saved

    def test_verify_detects_a_deleted_evidence_or_audit(self) -> None:
        self.run_op(gp.push)
        evidence = self.evidence("ITGRC-EV-AUDIT-CHAIN")
        del self.fake.evidences[evidence["id"]]
        with self.assertRaises(gp.DriftError):
            self.run_op(gp.verify)
        self.assertIn("DRIFT evidence ITGRC-EV-AUDIT-CHAIN is missing", self.output.getvalue())
        self.fake.audits.clear()
        with self.assertRaises(gp.DriftError):
            self.run_op(gp.verify)
        self.assertIn("DRIFT audit ITGRC-800-66R2 is missing", self.output.getvalue())
        self.assert_quiet()

    def test_a_changed_mapping_is_drift(self) -> None:
        self.run_op(gp.push)
        changed = self.data.parent / "mapping.json"
        raw = raw_mapping()
        raw["version"] = "2026-10-14.1"
        changed.write_text(json.dumps(raw))
        self.with_settings(mapping=changed)
        with self.assertRaises(gp.DriftError):
            self.run_op(gp.verify)
        self.assertIn("the mapping file changed since the last push", self.output.getvalue())


class SummaryTests(PushTestCase):
    def summary(self) -> str:
        start = len(self.output.getvalue())
        writes = len(self.fake.writes)
        self.run_op(gp.summary)
        self.assertEqual(self.fake.writes[writes:], [])
        return self.output.getvalue()[start:]

    def test_summary_reports_results_statuses_coverage_evidence_and_control(self) -> None:
        self.run_op(gp.push)
        printed = self.summary()
        for line in (
            "Audit ITGRC-800-66R2 ('IT GRC Lab' / ITGRC-LAB): status in_progress, not locked",
            "Results (118 assessable): not_assessed=98, partially_compliant=20",
            "Statuses: in_review=20, to_do=98",
            "Evidence coverage: covered=20, total=118, uncovered=98",
            "Evidence objects (9): in_review=9",
            "Applied control ITGRC-AC-KEY-ROTATION: status --, 1 evidence link(s)",
        ):
            self.assertIn(line, printed)
        self.assert_quiet()

    def test_summary_needs_an_audit_and_counts_missing_objects(self) -> None:
        with self.assertRaisesRegex(ops.OpsError, "run `it-grc push` first"):
            self.run_op(gp.summary)
        self.run_op(gp.push)
        del self.fake.evidences[self.evidence("ITGRC-EV-AUDIT-CHAIN")["id"]]
        self.fake.controls.clear()
        printed = self.summary()
        self.assertIn("Evidence objects (9): in_review=8, missing=1", printed)
        self.assertIn("Applied control ITGRC-AC-KEY-ROTATION: missing", printed)
        self.assert_quiet()


class CommandLineTests(unittest.TestCase):
    def test_push_without_a_report_is_refused_without_secrets(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        (root / "scripts").mkdir()
        (root / "scripts/grc_lab.py").write_text("")
        (root / "deploy").mkdir()
        with contextlib.redirect_stderr(io.StringIO()) as err:
            code = ops.run("push", root, operations=gp.OPERATIONS)
        self.assertEqual(code, 1)
        self.assertIn("push needs --report", err.getvalue())


if __name__ == "__main__":
    unittest.main()
