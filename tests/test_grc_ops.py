"""Offline tests for bootstrap, rotate-admin, token-refresh and bridge-check against an
in-memory CISO Assistant stand-in on loopback HTTPS. No VM and no external network."""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from grc_fake import OPENSSL, Certificates, FakeCiso, TlsServer, make_certificates

from it_grc import grc_ops as ops
from it_grc.grc_client import ClientOptions, GrcLookupError

ADMIN_PASSWORD = "Adm1n-" + "q" * 30


class VaultTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.redactor = ops.Redactor()
        self.vault = ops.Vault(Path(folder.name) / ".data", self.redactor)

    def test_files_and_directory_are_owner_only(self) -> None:
        self.vault.create("bridge-token", "T" * 64)
        path = self.vault.directory() / "bridge-token"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.vault.directory().stat().st_mode & 0o777, 0o700)
        self.vault.replace("bridge-token", "U" * 64)
        self.assertEqual(path.read_text(), "U" * 64)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertFalse(path.with_name("bridge-token.tmp").exists())
        self.assertEqual(self.vault.read("bridge-token"), "U" * 64)

    def test_create_never_overwrites(self) -> None:
        self.vault.create("bridge-password", "P" * 32)
        with self.assertRaises(ops.OpsError):
            self.vault.create("bridge-password", "Q" * 32)
        self.assertEqual(self.vault.read("bridge-password"), "P" * 32)

    def test_loose_linked_missing_or_malformed_files_are_refused(self) -> None:
        folder = self.vault.directory()
        loose = folder / "loose"
        loose.write_text("L" * 40)
        loose.chmod(0o640)
        (folder / "link").symlink_to(loose)
        short = folder / "short"
        short.write_text("abc")
        short.chmod(0o600)
        for name in ("loose", "link", "missing", "short"):
            with self.subTest(name=name), self.assertRaises(ops.OpsError):
                self.vault.read(name)
        with self.assertRaises(ops.OpsError):
            self.vault.create("bad", "has spaces in it and is long enough to pass")

    def test_permissive_directory_is_tightened_and_symlinked_one_refused(self) -> None:
        folder = self.vault.folder
        folder.mkdir(mode=0o755)
        folder.chmod(0o755)
        self.vault.directory()
        self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
        linked = ops.Vault(folder.parent / "linked", self.redactor)
        linked.folder.symlink_to(folder)
        with self.assertRaises(ops.OpsError):
            linked.directory()

    def test_redactor_hides_every_known_secret(self) -> None:
        self.redactor.add("A" * 40)
        self.redactor.add("A" * 40 + "B")
        self.assertEqual(self.redactor("x " + "A" * 40 + "B y"), "x <redacted> y")

    def test_generated_passwords_mix_character_classes(self) -> None:
        for _ in range(50):
            value = ops.generate_password()
            self.assertRegex(value, r"^[A-Za-z0-9_-]{32}$")
            self.assertRegex(value, r"[a-z]")
            self.assertRegex(value, r"[A-Z]")
            self.assertRegex(value, r"[0-9]")


@unittest.skipUnless(OPENSSL, "openssl is required to create a test CA")
class OperationsTestCase(unittest.TestCase):
    certificates: Certificates

    @classmethod
    def setUpClass(cls) -> None:
        cls.folder = Path(tempfile.mkdtemp())
        cls.certificates = make_certificates(cls.folder / "ca")

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.folder)

    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.data = Path(folder.name) / ".data"
        self.data.mkdir(mode=0o700)
        shutil.copy(self.certificates.ca, self.data / "ca.pem")
        self.write("admin-password", ADMIN_PASSWORD)
        self.fake = FakeCiso(ADMIN_PASSWORD, nodes=self.nodes())
        self.server = TlsServer(self.fake, self.certificates)
        self.addCleanup(self.server.stop)
        self.synced: list[str] = []
        self.output = io.StringIO()
        self.settings = ops.Settings(
            data=self.data,
            origin=self.server.origin(),
            options=ClientOptions(sleep=lambda _: None),
            sync_secret=self.sync,
        )

    def nodes(self) -> list[dict[str, Any]] | None:
        """Requirement nodes of the stand-in library; None for the generic 179 nodes."""
        return None

    def sync(self) -> list[str]:
        self.synced.append((self.data / "admin-password").read_text())
        return ["Updated Secret it-grc-bootstrap from deploy/.data/admin-password (verified)"]

    def write(self, name: str, value: str) -> None:
        path = self.data / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(value)

    def run_op(self, operation: Any) -> Any:
        redactor = ops.Redactor()
        with contextlib.redirect_stdout(self.output):
            return operation(self.settings, lambda m: print(redactor(m)), redactor)

    def secrets_seen(self) -> list[str]:
        values = [ADMIN_PASSWORD, *self.fake.issued]
        for name in ("admin-password", "bridge-password", "bridge-token"):
            if (self.data / name).exists():
                values.append((self.data / name).read_text())
        return values

    def assert_quiet(self) -> None:
        printed = self.output.getvalue()
        for value in self.secrets_seen():
            self.assertNotIn(value, printed)

    def mode(self, name: str) -> int:
        return (self.data / name).stat().st_mode & 0o777

    def bridge(self) -> dict[str, Any]:
        user = self.fake.user_by_email(ops.BRIDGE_EMAIL)
        assert user is not None
        return user


class BootstrapTests(OperationsTestCase):
    def test_bootstrap_creates_everything_once_and_is_idempotent(self) -> None:
        changes = self.run_op(ops.bootstrap)
        self.assertEqual(len(changes), 7)
        self.assertTrue(self.fake.library["is_loaded"])
        domains = [f for f in self.fake.folders.values() if f["name"] == ops.DOMAIN]
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0]["parent_folder"], self.fake.root)
        perimeters = list(self.fake.perimeters.values())
        self.assertEqual(
            [(p["name"], p["ref_id"]) for p in perimeters], [("Security lab", "ITGRC-LAB")]
        )
        analyst = [g["id"] for g in self.fake.groups.values() if g["name"] == ops.ANALYST_GROUP]
        self.assertEqual(self.bridge()["groups"], analyst)
        self.assertFalse(self.bridge()["is_superuser"])
        for name in ("bridge-password", "bridge-token"):
            self.assertEqual(self.mode(name), 0o600)
        self.assertEqual(self.data.stat().st_mode & 0o777, 0o700)
        token = (self.data / "bridge-token").read_text()
        self.assertEqual(self.fake.tokens[token]["user"], self.bridge()["id"])
        self.assertEqual(self.bridge()["password"], (self.data / "bridge-password").read_text())
        # Every session is closed: only the bridge token remains, no headless session.
        self.assertEqual(list(self.fake.tokens), [token])
        self.assertEqual(self.fake.sessions, {})

        writes = len(self.fake.writes)
        files = {n: (self.data / n).read_text() for n in ("bridge-password", "bridge-token")}
        self.assertEqual(self.run_op(ops.bootstrap), [])
        self.assertEqual(self.fake.writes[writes:], [])
        self.assertEqual({n: (self.data / n).read_text() for n in files}, files)
        self.assertEqual(list(self.fake.tokens), [token])
        self.assertEqual(self.fake.sessions, {})
        self.assertIn("Bootstrap complete: no changes", self.output.getvalue())
        self.assert_quiet()

    def test_bridge_user_is_reduced_to_the_analyst_group_only(self) -> None:
        self.run_op(ops.bootstrap)
        extra = [g["id"] for g in self.fake.groups.values() if g["name"].endswith("Domain manager")]
        self.bridge()["groups"] += extra
        changes = self.run_op(ops.bootstrap)
        self.assertEqual(len(changes), 1)
        analyst = [g["id"] for g in self.fake.groups.values() if g["name"] == ops.ANALYST_GROUP]
        self.assertEqual(self.bridge()["groups"], analyst)

    def test_superuser_or_inactive_bridge_user_is_refused(self) -> None:
        self.run_op(ops.bootstrap)
        for field in ("is_superuser", "is_active"):
            self.bridge()[field] = not self.bridge()[field]
            with self.subTest(field=field), self.assertRaises(ops.OpsError):
                self.run_op(ops.bootstrap)
            self.bridge()[field] = not self.bridge()[field]
        self.assertEqual(self.fake.sessions, {})

    def test_an_ignored_email_filter_stops_before_any_user_write(self) -> None:
        self.fake.add_user("someone@example.org", None)
        self.fake.ignored_filters.add(("/api/users/", "email"))
        with self.assertRaises(GrcLookupError):
            self.run_op(ops.bootstrap)
        self.assertNotIn(("POST", "/api/users/"), self.fake.writes)
        self.assertIsNone(self.fake.user_by_email(ops.BRIDGE_EMAIL))

    def test_lost_bridge_password_file_is_regenerated_and_stale_token_replaced(self) -> None:
        self.run_op(ops.bootstrap)
        old_token = (self.data / "bridge-token").read_text()
        (self.data / "bridge-password").unlink()
        del self.fake.tokens[old_token]
        changes = self.run_op(ops.bootstrap)
        self.assertEqual(len(changes), 2)
        self.assertNotEqual((self.data / "bridge-token").read_text(), old_token)
        self.assertEqual(self.mode("bridge-password"), 0o600)

    def test_wrong_admin_password_is_reported_without_the_value(self) -> None:
        (self.data / "admin-password").unlink()
        self.write("admin-password", "Wrong-" + "w" * 30)
        with self.assertRaises(ops.OpsError) as raised:
            self.run_op(ops.bootstrap)
        self.assertNotIn("Wrong-", str(raised.exception))
        self.assertEqual(self.fake.writes, [])


class RotationTests(OperationsTestCase):
    def test_rotation_changes_the_password_and_revokes_old_access(self) -> None:
        exposed_pat = self.fake.issue(self.fake.admin, name="left-over")
        self.run_op(ops.rotate_admin)
        new = (self.data / "admin-password").read_text()
        self.assertNotEqual(new, ADMIN_PASSWORD)
        self.assertEqual(self.mode("admin-password"), 0o600)
        self.assertFalse((self.data / "admin-password.pending").exists())
        self.assertEqual(self.fake.users[self.fake.admin]["password"], new)
        self.assertNotIn(exposed_pat, self.fake.tokens)
        self.assertEqual(self.fake.tokens, {})
        self.assertEqual(self.fake.sessions, {})
        self.assertEqual(self.synced, [new])
        printed = self.output.getvalue()
        self.assertIn("PASS the old administrator password is rejected", printed)
        self.assertNotIn(new, printed)
        self.assertNotIn(ADMIN_PASSWORD, printed)

    def test_a_pending_rotation_that_already_applied_is_finished(self) -> None:
        pending = "Pend1ng-" + "p" * 30
        self.write("admin-password.pending", pending)
        self.fake.users[self.fake.admin]["password"] = pending
        self.run_op(ops.rotate_admin)
        self.assertEqual((self.data / "admin-password").read_text(), pending)
        self.assertFalse((self.data / "admin-password.pending").exists())
        self.assertNotIn(("POST", "/api/iam/change-password/"), self.fake.writes)
        self.assertEqual(self.synced, [pending])

    def test_a_pending_rotation_that_never_applied_is_discarded(self) -> None:
        self.write("admin-password.pending", "Stale1-" + "s" * 30)
        self.run_op(ops.rotate_admin)
        new = (self.data / "admin-password").read_text()
        self.assertNotIn(new, {ADMIN_PASSWORD, "Stale1-" + "s" * 30})
        self.assertEqual(self.fake.users[self.fake.admin]["password"], new)

    def test_a_rejected_current_password_changes_nothing(self) -> None:
        self.fake.users[self.fake.admin]["password"] = "Other1-" + "o" * 30
        with self.assertRaises(ops.OpsError):
            self.run_op(ops.rotate_admin)
        self.assertEqual((self.data / "admin-password").read_text(), ADMIN_PASSWORD)
        self.assertFalse((self.data / "admin-password.pending").exists())
        self.assertEqual(self.synced, [])


class TokenTests(OperationsTestCase):
    def test_refresh_issues_a_new_token_and_revokes_the_old_one(self) -> None:
        self.run_op(ops.bootstrap)
        old = (self.data / "bridge-token").read_text()
        orphan = self.fake.issue(self.bridge()["id"], name="orphan")
        self.run_op(ops.token_refresh)
        new = (self.data / "bridge-token").read_text()
        self.assertNotEqual(new, old)
        self.assertEqual(self.mode("bridge-token"), 0o600)
        self.assertNotIn(old, self.fake.tokens)
        self.assertNotIn(orphan, self.fake.tokens)
        self.assertEqual(list(self.fake.tokens), [new])
        self.assertEqual(self.fake.tokens[new]["user"], self.bridge()["id"])
        self.assertIn("Revoked 2 previous token(s)", self.output.getvalue())
        self.assert_quiet()

    def test_refresh_at_the_token_limit_still_succeeds(self) -> None:
        self.run_op(ops.bootstrap)
        for index in range(4):
            self.fake.issue(self.bridge()["id"], name=f"extra-{index}")
        self.run_op(ops.token_refresh)
        self.assertEqual(len(self.fake.pats(self.bridge()["id"])), 1)

    def test_bridge_check_reads_the_framework_and_is_denied_writes(self) -> None:
        self.run_op(ops.bootstrap)
        writes = len(self.fake.writes)
        self.run_op(ops.bridge_check)
        printed = self.output.getvalue()
        self.assertIn("179 requirement nodes, 152 assessable", printed)
        self.assertIn("cannot load a library (HTTP 403)", printed)
        self.assertIn("cannot create a domain (HTTP 403)", printed)
        self.assertEqual(
            self.fake.writes[writes:],
            [
                ("POST", f"/api/stored-libraries/{self.fake.library['id']}/import/"),
                ("POST", "/api/folders/"),
            ],
        )
        self.assertEqual(
            len([f for f in self.fake.folders.values() if f["name"] == ops.PROBE_DOMAIN]), 0
        )
        self.assert_quiet()

    def test_bridge_check_fails_for_a_superuser_or_a_second_role(self) -> None:
        self.run_op(ops.bootstrap)
        manager = [g["id"] for g in self.fake.groups.values() if g["name"].endswith("manager")]
        for change in ("superuser", "second role"):
            saved = (self.bridge()["is_superuser"], list(self.bridge()["groups"]))
            if change == "superuser":
                self.bridge()["is_superuser"] = True
            else:
                self.bridge()["groups"] += manager
            with self.subTest(change=change), self.assertRaises(ops.OpsError):
                self.run_op(ops.bridge_check)
            self.bridge()["is_superuser"], self.bridge()["groups"] = saved


class CommandLineTests(unittest.TestCase):
    def test_commands_outside_a_checkout_are_refused(self) -> None:
        with (
            tempfile.TemporaryDirectory() as folder,
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            self.assertEqual(ops.run("bootstrap", Path(folder)), 2)
        self.assertIn("repository checkout", err.getvalue())

    def test_errors_are_printed_redacted(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        (root / "scripts").mkdir()
        (root / "scripts/grc_lab.py").write_text("")
        (root / "deploy").mkdir()
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(ops.run("token-refresh", root), 1)
        self.assertIn("it-grc: ", err.getvalue())
        self.assertIn("CA certificate file is missing", err.getvalue())


if __name__ == "__main__":
    unittest.main()
