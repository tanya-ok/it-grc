"""Offline tests for the hash-chained push ledger and its checkpoint, and for verify against
the in-memory CISO Assistant stand-in on loopback HTTPS. No VM and no external network."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from grc_fake import NODE_PREFIX
from test_grc_push import MAPPING, REPORT, PushTestCase

from it_grc import grc_ledger as gl
from it_grc import grc_ops as ops
from it_grc import grc_push as gp

ROOT = Path(__file__).resolve().parent.parent


def independent_hash(record: dict[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "record_hash"}
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode()).hexdigest()


def canonical_line(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


class LedgerFileTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name) / ".data"
        self.folder.mkdir(mode=0o700)
        self.redactor = ops.Redactor()
        self.records = [self.add(note=f"push {index}") for index in range(1, 4)]

    def add(self, **body: Any) -> dict[str, Any]:
        record = {"time": "2026-10-13T12:00:00Z", "outcome": "complete", **body}
        return gl.append(self.folder, record, self.redactor)

    @property
    def ledger(self) -> Path:
        return self.folder / gl.LEDGER_FILE

    def lines(self) -> list[bytes]:
        return self.ledger.read_bytes().splitlines()

    def rewrite(self, lines: list[bytes]) -> None:
        # Opening the existing file keeps its mode, as an in-place edit would.
        with self.ledger.open("wb") as handle:
            handle.write(b"".join(line + b"\n" for line in lines))

    def assert_refused(self, needle: str) -> None:
        with self.assertRaises(gl.LedgerError) as raised:
            gl.verify_ledger(self.folder)
        self.assertIn(needle, str(raised.exception))

    def test_chain_verifies_and_files_are_owner_only(self) -> None:
        state = gl.verify_ledger(self.folder)
        self.assertEqual([r["seq"] for r in state.records], [1, 2, 3])
        self.assertEqual(state.records[0]["prev_hash"], gl.GENESIS)
        for before, after in zip(state.records, state.records[1:], strict=False):
            self.assertEqual(after["prev_hash"], before["record_hash"])
        for record in state.records:
            self.assertEqual(record["record_hash"], independent_hash(record))
        self.assertEqual(self.lines(), [canonical_line(r) for r in self.records])
        self.assertEqual((state.checkpoint, state.warnings), (3, ()))
        checkpoint = json.loads((self.folder / gl.CHECKPOINT_FILE).read_text())
        self.assertEqual(checkpoint["count"], 3)
        self.assertEqual(checkpoint["record_hash"], self.records[-1]["record_hash"])
        for name in (gl.LEDGER_FILE, gl.CHECKPOINT_FILE):
            self.assertEqual((self.folder / name).stat().st_mode & 0o777, 0o600)
        names = sorted(path.name for path in self.folder.iterdir())
        self.assertEqual(names, sorted([gl.LEDGER_FILE, gl.CHECKPOINT_FILE]))

    def test_an_edited_record_is_detected(self) -> None:
        original = self.lines()

        def edited(index: int, *, rehash: bool) -> dict[str, Any]:
            record = json.loads(original[index])
            record["note"] = "changed"
            if rehash:
                record["record_hash"] = independent_hash(record)
            return dict(record)

        cases = [
            ("does not match its record_hash", 1, edited(1, rehash=False)),
            ("record 3 does not chain", 1, edited(1, rehash=True)),
            ("does not match the checkpoint", 2, edited(2, rehash=True)),
        ]
        for needle, index, record in cases:
            with self.subTest(needle=needle):
                lines = list(original)
                lines[index] = canonical_line(record)
                self.rewrite(lines)
                self.assert_refused(needle)
        lines = list(original)
        lines[1] = json.dumps(json.loads(original[1]), sort_keys=True).encode()
        self.rewrite(lines)
        self.assert_refused("not in canonical form")

    def test_reordered_records_are_detected(self) -> None:
        first, second, third = self.lines()
        self.rewrite([first, third, second])
        self.assert_refused("record 2 has the wrong sequence number")

    def test_deleted_records_are_detected(self) -> None:
        first, second, third = self.lines()
        self.rewrite([first, third])
        self.assert_refused("record 2 has the wrong sequence number")
        self.rewrite([second, third])
        self.assert_refused("record 1 has the wrong sequence number")

    def test_tail_truncation_is_detected_by_the_checkpoint(self) -> None:
        lines = self.lines()
        self.rewrite(lines[:2])
        self.assert_refused("records were removed from the end")
        self.rewrite([])
        self.assert_refused("records were removed from the end")
        self.ledger.unlink()
        self.assert_refused("records were removed from the end")

    def test_rewriting_both_files_is_not_detected(self) -> None:
        # The documented limit: the checkpoint beside the ledger is not tamper-proof.
        self.rewrite(self.lines()[:2])
        gl.write_checkpoint(self.folder, 2, self.records[1]["record_hash"])
        self.assertEqual(len(gl.verify_ledger(self.folder).records), 2)

    def test_a_missing_or_lagging_checkpoint(self) -> None:
        gl.write_checkpoint(self.folder, 2, self.records[1]["record_hash"])
        state = gl.verify_ledger(self.folder)
        self.assertEqual(len(state.warnings), 1)
        self.assertIn("covers 2 of 3 records", state.warnings[0])
        self.add(note="push 4")
        self.assertEqual(gl.verify_ledger(self.folder).warnings, ())
        (self.folder / gl.CHECKPOINT_FILE).unlink()
        self.assert_refused("is missing")
        gl.write_checkpoint(self.folder, 1, self.records[2]["record_hash"])
        self.assert_refused("record 1 does not match the checkpoint")

    def test_an_incomplete_or_malformed_file_is_refused(self) -> None:
        with self.ledger.open("ab") as handle:
            handle.write(b'{"kind":"it-grc-ledger-record"')
        self.assert_refused("the last line is incomplete")
        self.rewrite([*self.lines()[:3], b"not json"])
        self.assert_refused("record 4 is not valid JSON")
        self.rewrite(self.lines()[:3])
        (self.folder / gl.CHECKPOINT_FILE).write_text("{}\n")
        self.assert_refused("is malformed")

    def test_loose_or_linked_files_are_refused(self) -> None:
        self.ledger.chmod(0o644)
        self.assert_refused("owner-only (0600)")
        self.ledger.chmod(0o600)
        moved = self.folder.parent / "elsewhere.jsonl"
        self.ledger.rename(moved)
        self.ledger.symlink_to(moved)
        self.assert_refused("cannot be opened safely")

    def test_append_refuses_a_broken_ledger_secrets_and_chain_fields(self) -> None:
        first, second, third = self.lines()
        self.rewrite([first, third, second])
        with self.assertRaises(gl.LedgerError):
            self.add(note="push 4")
        self.assertEqual(self.lines(), [first, third, second])
        self.rewrite([first, second, third])
        secret = "S3cret-" + "s" * 40
        self.redactor.add(secret)
        with self.assertRaisesRegex(gl.LedgerError, "contains a secret"):
            self.add(note=f"token {secret}")
        with self.assertRaisesRegex(gl.LedgerError, "chain fields"):
            self.add(prev_hash=gl.GENESIS)
        self.assertEqual(self.lines(), [first, second, third])
        self.assertEqual(gl.verify_ledger(self.folder).checkpoint, 3)

    def test_ledger_verify_command(self) -> None:
        output: list[str] = []
        settings = ops.Settings(data=self.folder)
        gl.ledger_verify(settings, output.append, self.redactor)
        self.assertIn("PASS ledger: 3 record(s)", output[0])
        self.assertIn("PASS checkpoint: record 3", output[1])
        self.assertIn(self.records[-1]["record_hash"], output[2])


class LedgerPushTests(PushTestCase):
    def records(self) -> tuple[dict[str, Any], ...]:
        return gl.verify_ledger(self.data).records

    def test_a_real_push_appends_one_record_and_a_dry_run_none(self) -> None:
        self.with_settings(dry_run=True)
        self.run_op(gp.push)
        self.assertFalse((self.data / gl.LEDGER_FILE).exists())
        self.with_settings(dry_run=False)
        changes = self.run_op(gp.push)
        (record,) = self.records()
        self.assertEqual(
            (record["seq"], record["prev_hash"], record["outcome"], record["ce_version"]),
            (1, gl.GENESIS, "complete", "v4.1.1"),
        )
        self.assertEqual(record["actor"], ops.BRIDGE_EMAIL)
        audit = next(iter(self.fake.audits.values()))
        self.assertEqual(record["audit"], {"id": audit["id"], "ref_id": "ITGRC-800-66R2"})
        self.assertEqual(
            record["report"]["artifact_sha256"], hashlib.sha256(REPORT.read_bytes()).hexdigest()
        )
        self.assertEqual(
            record["mapping"]["sha256"], hashlib.sha256(MAPPING.read_bytes()).hexdigest()
        )
        self.assertEqual(record["writes"], changes)
        self.assertEqual(len(record["requirements"]), 117)
        for row in record["requirements"]:
            self.assertEqual(row["observed"], row["planned"])
            self.assertIsNone(row["held"])
        self.assertEqual(len(record["evidence"]), 9)
        for item, entry in zip(self.plan.extracts, record["evidence"], strict=True):
            self.assertEqual(entry["id"], self.evidence(item.group.ref_id)["id"])
            (revision,) = entry["revisions"]
            stored = self.revisions(item.group.ref_id)[0]
            self.assertEqual(
                revision, {"id": stored["id"], "version": 1, "attachment_hash": item.sha256}
            )
        (control,) = record["controls"]
        self.assertEqual(control["evidence"], [self.evidence("ITGRC-EV-KEY-ROTATION")["id"]])
        self.assertIn("Ledger: appended record 1", self.output.getvalue())

        # A push without changes still adds a record; a dry run adds none.
        self.assertEqual(self.run_op(gp.push), [])
        self.with_settings(dry_run=True)
        self.run_op(gp.push)
        first, second = self.records()
        self.assertEqual((second["seq"], second["writes"]), (2, []))
        self.assertEqual(second["prev_hash"], first["record_hash"])
        self.assertEqual(gl.verify_ledger(self.data).checkpoint, 2)

    def test_records_hold_no_secrets(self) -> None:
        self.run_op(gp.push)
        self.run_op(gp.verify)
        stored = b"".join(
            (self.data / name).read_bytes() for name in (gl.LEDGER_FILE, gl.CHECKPOINT_FILE)
        )
        for value in self.secrets_seen():
            self.assertNotIn(value.encode(), stored)
        self.assertNotIn(b"Token ", stored)
        self.assert_quiet()

    def test_held_decisions_are_recorded_and_are_not_drift(self) -> None:
        self.run_op(gp.push)
        self.assessment("node211").update(result="compliant", status="done")
        self.run_op(gp.push)
        entry = next(
            r for r in self.records()[-1]["requirements"] if r["urn"] == NODE_PREFIX + "node211"
        )
        self.assertEqual(entry["observed"], {"result": "compliant", "status": "done"})
        self.assertEqual(entry["held"], "result compliant")
        self.assessment("node57").update(status="in_progress")
        self.assertEqual(self.run_op(gp.verify), [])
        printed = self.output.getvalue()
        self.assertIn(f"HELD {NODE_PREFIX}node211 (164.312(a)(1)): result compliant;", printed)
        self.assertIn("recorded at the push", printed)
        self.assertIn(f"HELD {NODE_PREFIX}node57", printed)
        self.assertIn("a human decision since the push", printed)
        self.assertIn("2 requirement(s) held by human decisions", printed)

    def test_a_changed_result_that_no_human_holds_is_drift(self) -> None:
        self.run_op(gp.push)
        self.assessment("node211").update(result="non_compliant")
        with self.assertRaises(gp.DriftError):
            self.run_op(gp.verify)
        self.assertIn(
            f"{NODE_PREFIX}node211 (164.312(a)(1)) result is non_compliant, the ledger recorded"
            " partially_compliant",
            self.output.getvalue(),
        )

    def test_missing_and_unrecorded_revisions_are_drift(self) -> None:
        self.run_op(gp.push)
        saved = copy.deepcopy(self.fake.revisions)
        (revision,) = self.revisions("ITGRC-EV-ACCESS")
        del self.fake.revisions[revision["id"]]
        with self.assertRaises(gp.DriftError):
            self.run_op(gp.verify)
        self.assertIn("ITGRC-EV-ACCESS revision 1 in the ledger is missing", self.output.getvalue())
        self.fake.revisions = saved
        extra = {**copy.deepcopy(revision), "id": "0f0f0f0f-0000-4000-8000-000000000001"}
        extra["version"] = 2
        self.fake.revisions[extra["id"]] = extra
        with self.assertRaises(gp.DriftError):
            self.run_op(gp.verify)
        self.assertIn("ITGRC-EV-ACCESS revision 2 is not in the ledger", self.output.getvalue())

    def test_a_failed_push_is_recorded_and_reported_by_verify(self) -> None:
        self.run_op(gp.push)
        self.with_settings(report=self.changed_report())
        self.fake.corrupt_hashes = True
        with self.assertRaisesRegex(ops.OpsError, "differs from the local sha256"):
            self.run_op(gp.push)
        _, failed = self.records()
        self.assertEqual((failed["outcome"], len(failed["writes"])), ("failed", 1))
        self.assertTrue(failed["writes"][0].startswith("upload ITGRC-EV-ACCESS revision 2"))
        self.assertIn("differs from the local sha256", failed["error"])
        self.assertNotIn("requirements", failed)
        self.fake.corrupt_hashes = False
        with self.assertRaises(gp.DriftError):
            self.run_op(gp.verify)
        printed = self.output.getvalue()
        self.assertIn("ledger record 2 is a push that failed after 1 write(s)", printed)
        self.assertIn("comparing with record 1", printed)
        self.assertIn("ITGRC-EV-ACCESS revision 2 is not in the ledger", printed)
        self.assert_quiet()

    def test_a_broken_ledger_stops_push_and_verify_before_any_write(self) -> None:
        self.run_op(gp.push)
        self.run_op(gp.push)
        path = self.data / gl.LEDGER_FILE
        first, second = path.read_bytes().splitlines()
        with path.open("wb") as handle:
            handle.write(second + b"\n" + first + b"\n")
        writes = len(self.fake.writes)
        for operation in (gp.push, gp.verify):
            with self.subTest(operation=operation.__name__), self.assertRaises(gl.LedgerError):
                self.run_op(operation)
        self.assertEqual(self.fake.writes[writes:], [])


class CommandLineTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "scripts").mkdir()
            (root / "scripts/grc_lab.py").write_text("")
            (root / "deploy/.data").mkdir(parents=True, mode=0o700)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "IT_GRC_ROOT": str(root)}
            return subprocess.run(
                [sys.executable, "-m", "it_grc", *args],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
                env=env,
            )

    def test_ledger_needs_the_verify_action(self) -> None:
        done = self.run_cli("ledger")
        self.assertEqual(done.returncode, 2)
        self.assertIn("use `ledger verify`", done.stderr)
        self.assertEqual(self.run_cli("verify", "verify").returncode, 2)

    def test_ledger_verify_runs_offline(self) -> None:
        done = self.run_cli("ledger", "verify")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("holds no records yet", done.stdout)


if __name__ == "__main__":
    unittest.main()
