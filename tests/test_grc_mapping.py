"""Offline tests for the versioned NIST SP 800-66 rev2 mapping and the push plan."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from it_grc import grc_mapping as gm

ROOT = Path(__file__).resolve().parent.parent
MAPPING = ROOT / "mappings/hipaa-800-66r2.json"
REPORT = ROOT / "fixtures/lab/demo-report-2026-10-13.json"


def raw_mapping() -> dict[str, Any]:
    value: dict[str, Any] = json.loads(MAPPING.read_text())
    return value


def parse(raw: dict[str, Any]) -> gm.MappingFile:
    return gm.parse_mapping(raw, "0" * 64)


class MappingTests(unittest.TestCase):
    def test_repository_mapping_is_valid_and_complete(self) -> None:
        mapping = gm.load_mapping(MAPPING)
        self.assertRegex(mapping.version, gm.VERSION)
        evidenced = [t for t in mapping.targets if t.gap is None]
        gaps = [t for t in mapping.targets if t.gap is not None]
        self.assertEqual((len(evidenced), len(gaps)), (20, 97))
        for target in mapping.targets:
            self.assertRegex(target.urn, gm.NODE_URN)
            self.assertNotEqual(target.result, "compliant")
            self.assertNotEqual(target.status, "done")
        self.assertEqual(
            {(t.result, t.status) for t in evidenced}, {("partially_compliant", "in_review")}
        )
        self.assertEqual({(t.result, t.status) for t in gaps}, {("not_assessed", "to_do")})
        covered = {n for group in mapping.groups for n in group.scenarios}
        self.assertEqual(covered, set(range(1, 19)))
        sensitive = {t.urn.rsplit(":", 1)[1] for t in evidenced if t.extended_result}
        self.assertEqual(sensitive, {"node211", "node258"})
        self.assertEqual([c.name for c in mapping.controls], ["Signing key rotation with overlap"])
        gap_ids = {t.gap for t in gaps}
        for expected in (
            "physical-safeguards",
            "risk-analysis",
            "business-associate-contracts",
            "organizational-requirements",
            "documentation-retention",
        ):
            self.assertIn(expected, gap_ids)

    def test_urns_must_be_nist_800_66_nodes(self) -> None:
        for urn in (
            "urn:intuitem:risk:req_node:nist-sp-800-53-rev5:node211",
            "urn:intuitem:risk:req_node:nist-sp-800-66-rev2:164.312(a)",
            "urn:intuitem:risk:req_node:nist-sp-800-66-rev2:node211 ",
        ):
            raw = raw_mapping()
            raw["requirements"][0]["urn"] = urn
            with self.subTest(urn=urn), self.assertRaises(gm.MappingError):
                parse(raw)
        raw = raw_mapping()
        raw["not_verified"][0]["nodes"][0]["urn"] = raw["requirements"][0]["urn"]
        with self.assertRaisesRegex(gm.MappingError, "mapped twice"):
            parse(raw)

    def test_a_mapping_asking_for_compliant_or_done_is_refused(self) -> None:
        cases = [
            ("requirements", "result", "compliant"),
            ("requirements", "status", "done"),
            ("requirements", "result", "not_applicable"),
            ("not_verified", "result", "compliant"),
            ("not_verified", "status", "done"),
        ]
        for section, key, value in cases:
            raw = raw_mapping()
            raw[section][0][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(gm.CeilingError):
                parse(raw)
        raw = raw_mapping()
        raw["ceiling"] = {"result": "compliant", "status": "done"}
        with self.assertRaises(gm.CeilingError):
            parse(raw)

    def test_unknown_fields_references_and_dashes_are_refused(self) -> None:
        mutations = [
            lambda raw: raw["requirements"][0].update(extra=True),
            lambda raw: raw["requirements"][0].update(evidence=["ITGRC-EV-UNKNOWN"]),
            lambda raw: raw["requirements"][0].update(rationale="A " + chr(0x2014) + " dash"),
            lambda raw: raw["requirements"][0].update(extended_result="major_nonconformity"),
            lambda raw: raw["evidence_groups"][0].update(scenarios=[1, 19]),
            lambda raw: raw["evidence_groups"].pop(),
            lambda raw: raw["audit"].update(ref_id="OTHER"),
            lambda raw: raw.update(framework="urn:intuitem:risk:framework:iso27001-2022"),
        ]
        for index, mutate in enumerate(mutations):
            raw = raw_mapping()
            mutate(raw)
            with self.subTest(index=index), self.assertRaises(gm.MappingError):
                parse(raw)

    def test_the_report_passes_the_strict_validator(self) -> None:
        report = json.loads(REPORT.read_text())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            for mutate in (
                lambda r: r["results"].pop(),
                lambda r: r.update(passed=False),
                lambda r: r.update(backend="docker"),
            ):
                broken = copy.deepcopy(report)
                mutate(broken)
                path.write_text(json.dumps(broken))
                with self.assertRaisesRegex(gm.MappingError, "lab report was refused"):
                    gm.load_report(path)

    def test_plan_is_deterministic_and_failures_lower_the_result(self) -> None:
        mapping = gm.load_mapping(MAPPING)
        first = gm.build_plan(mapping, gm.load_report(REPORT))
        second = gm.build_plan(mapping, gm.load_report(REPORT))
        self.assertEqual([e.content for e in first.extracts], [e.content for e in second.extracts])
        for item in first.extracts:
            self.assertNotIn(b"description", item.content)
        gap = next(p for p in first.requirements if p.target.gap)
        self.assertTrue(gap.observation.startswith("not_verified: "))
        report = gm.load_report(REPORT)
        for row in report["scenarios"]:
            if row["id"] in {11, 14}:
                row["passed"] = False
        plan = gm.build_plan(mapping, report)
        by_urn = {p.target.urn.rsplit(":", 1)[1]: p for p in plan.requirements}
        self.assertEqual(by_urn["node236"].result, "non_compliant")
        self.assertIn("Failed in the report: S14.", by_urn["node236"].observation)
        # S11 is supporting evidence only: it is reported but does not change the result.
        self.assertEqual(by_urn["node258"].result, "partially_compliant")
        self.assertIn("S11", by_urn["node258"].observation)
        self.assertNotEqual(
            plan.extract("ITGRC-EV-AUDIT-CHAIN").sha256,
            first.extract("ITGRC-EV-AUDIT-CHAIN").sha256,
        )


if __name__ == "__main__":
    unittest.main()
