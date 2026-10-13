"""Offline safety checks for scripts/grc_lab.py. No VM, process or network is used."""

from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import importlib.util
import io
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("grc_lab", ROOT / "scripts/grc_lab.py")
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


def owned_vm(**config: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "vmType": "vz",
        "param": {"owner": "it-grc"},
        "ssh": {"forwardAgent": False, "loadDotSSHPubKeys": False},
        "containerd": {"system": False, "user": False},
        "portForwards": [
            {
                "guestIP": "127.0.0.1",
                "guestPortRange": [18443, 18443],
                "hostIP": "127.0.0.1",
                "hostPortRange": [18443, 18443],
                "proto": "tcp",
            },
            {
                "guestIP": "0.0.0.0",
                "guestPortRange": [1, 65535],
                "hostIP": "127.0.0.1",
                "hostPortRange": [1, 65535],
                "proto": "any",
                "ignore": True,
            },
        ],
    }
    base.update(config)
    return {"name": "it-grc", "status": "Running", "config": base}


class OfflineTestCase(unittest.TestCase):
    """Any real process, socket or URL access fails the test."""

    def setUp(self) -> None:
        refuse = AssertionError("unit tests must not reach a VM or the network")
        for target in (
            patch.object(lab.subprocess, "run", side_effect=refuse),
            patch.object(lab.urllib.request, "urlopen", side_effect=refuse),
            patch.object(lab.http.client, "HTTPSConnection", side_effect=refuse),
        ):
            target.start()
            self.addCleanup(target.stop)
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        data = patch.object(lab, "DATA", Path(folder.name) / ".data")
        data.start()
        self.addCleanup(data.stop)
        self.addCleanup(lab._SECRETS.clear)


class VmIdentityTests(OfflineTestCase):
    def test_owned_vm_is_accepted(self) -> None:
        lab.verify_instance(owned_vm())

    def test_foreign_or_unsafe_vms_are_refused(self) -> None:
        forwards = owned_vm()["config"]["portForwards"]
        variants = [
            {**owned_vm(), "name": "security-lab"},
            owned_vm(param={}),
            owned_vm(param={"owner": "mcp-svid-auth"}),
            owned_vm(mounts=[{"location": "~", "writable": False}]),
            owned_vm(vmType="qemu"),
            owned_vm(ssh={"forwardAgent": True, "loadDotSSHPubKeys": False}),
            owned_vm(ssh={"forwardAgent": False, "loadDotSSHPubKeys": True}),
            owned_vm(containerd={"system": True, "user": False}),
            owned_vm(portForwards=[forwards[0]]),
            owned_vm(portForwards=[{**forwards[0], "hostIP": "0.0.0.0"}, forwards[1]]),
            owned_vm(
                portForwards=[
                    forwards[0],
                    {**forwards[0], "guestPortRange": [6443, 6443], "hostPortRange": [6443, 6443]},
                    forwards[1],
                ]
            ),
            None,
        ]
        for item in variants:
            with self.subTest(item=item), self.assertRaises(lab.GrcLabError):
                lab.verify_instance(item)

    def test_stopped_vm_is_refused_where_running_is_required(self) -> None:
        stopped = {**owned_vm(), "status": "Stopped"}
        lab.verify_instance(stopped, running=False)
        with self.assertRaises(lab.GrcLabError):
            lab.verify_instance(stopped)

    def test_foreign_vm_is_refused_before_stop_or_delete(self) -> None:
        foreign = owned_vm(param={})
        operations = [(lab.stop, False), (lab.destroy, True), (lab.down, False)]
        for operation, yes in operations:
            with (
                self.subTest(operation=operation.__name__),
                patch.object(lab, "command", return_value=json.dumps(foreign)) as call,
                self.assertRaises(lab.GrcLabError),
            ):
                operation(argparse.Namespace(yes=yes))
            call.assert_called_once_with(["limactl", "list", "--json"])

    def test_destroy_without_yes_touches_nothing(self) -> None:
        with patch.object(lab, "command") as call, self.assertRaises(lab.GrcLabError):
            lab.destroy(argparse.Namespace(yes=False))
        call.assert_not_called()

    def test_foreign_namespace_is_refused_before_uninstall(self) -> None:
        foreign = {"metadata": {"name": "it-grc", "labels": {lab.OWNER_KEY: "someone-else"}}}
        with (
            patch.object(lab, "require_vm", return_value=owned_vm()),
            patch.object(lab, "kube", return_value=json.dumps(foreign)) as kube,
            patch.object(lab, "helm") as helm,
            patch.object(lab, "guest") as guest,
            self.assertRaises(lab.GrcLabError),
        ):
            lab.down(argparse.Namespace())
        self.assertEqual(kube.call_count, 1)
        helm.assert_not_called()
        guest.assert_not_called()

    def test_guest_commands_only_target_the_it_grc_vm(self) -> None:
        with patch.object(lab, "command", return_value="") as call:
            lab.kube(["get", "pods"])
            lab.helm(["list"])
        for recorded in call.call_args_list:
            self.assertEqual(
                recorded.args[0][:6], ["limactl", "shell", "--workdir", "/", "it-grc", "sudo"]
            )


class SecretFileTests(OfflineTestCase):
    def test_generated_files_are_owner_only_without_newline(self) -> None:
        value, generated = lab.ensure_private("token", lambda: "A" * 40)
        path = lab.DATA / "token"
        self.assertTrue(generated)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(lab.DATA.stat().st_mode & 0o777, 0o700)
        self.assertEqual(path.read_bytes(), b"A" * 40)
        again, generated = lab.ensure_private("token", lambda: "B" * 40)
        self.assertEqual((again, generated), (value, False))

    def test_permissive_or_linked_files_are_refused(self) -> None:
        lab.private_dir()
        loose = lab.DATA / "loose"
        loose.write_text("C" * 40)
        loose.chmod(0o640)
        link = lab.DATA / "link"
        link.symlink_to(loose)
        for path in (loose, link, lab.DATA / "missing"):
            with self.subTest(path=path.name), self.assertRaises(lab.GrcLabError):
                lab.read_private(path)

    def test_permissive_data_directory_is_tightened(self) -> None:
        lab.DATA.mkdir(mode=0o755)
        lab.DATA.chmod(0o755)
        lab.private_dir()
        self.assertEqual(lab.DATA.stat().st_mode & 0o777, 0o700)

    def test_replaced_files_stay_owner_only(self) -> None:
        lab.write_private(lab.DATA / "ca.pem", "first")
        lab.write_private(lab.DATA / "ca.pem", "second", replace=True)
        self.assertEqual((lab.DATA / "ca.pem").read_text(), "second")
        self.assertEqual((lab.DATA / "ca.pem").stat().st_mode & 0o777, 0o600)


class OutputSecrecyTests(OfflineTestCase):
    def test_bootstrap_never_prints_or_places_the_password_on_argv(self) -> None:
        calls: list[tuple[list[str], bytes | None]] = []

        def kube(args: list[str], *, data: bytes | None = None, timeout: int = 300) -> str:
            calls.append((args, data))
            return ""

        answers = iter([(400, b"{}"), (200, b'{"meta": {"access_token": "' + b"T" * 64 + b'"}}')])

        def https(method: str, path: str, **_: Any) -> tuple[int, bytes]:
            return next(answers) if path.endswith("/auth/login") else (204, b"")

        output, errors = io.StringIO(), io.StringIO()
        with (
            patch.object(lab, "require_vm", return_value=owned_vm()),
            patch.object(lab, "owned_namespace", return_value={}),
            patch.object(lab, "kube", side_effect=kube),
            patch.object(lab, "https", side_effect=https),
            patch.object(lab, "wait_ready"),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            lab.bootstrap_admin(argparse.Namespace())
        password = (lab.DATA / lab.ADMIN_CREDENTIAL_FILE).read_text()
        printed = output.getvalue() + errors.getvalue()
        self.assertIn("Created the administrator", printed)
        self.assertNotIn(password, printed)
        self.assertNotIn("T" * 64, printed)
        self.assertFalse(any(password in " ".join(args) for args, _ in calls))
        carriers = [args for args, data in calls if data == password.encode()]
        self.assertEqual(len(carriers), 1)
        self.assertIn("--from-file=admin-password=/dev/stdin", carriers[0])

    def test_admin_secret_sync_sends_the_password_on_stdin_only(self) -> None:
        password, _ = lab.ensure_private(lab.ADMIN_CREDENTIAL_FILE, lambda: "R" * 32)
        calls: list[tuple[list[str], bytes | None]] = []
        stored = {"value": b""}

        def kube(args: list[str], *, data: bytes | None = None, timeout: int = 300) -> str:
            calls.append((args, data))
            if "--from-file=admin-password=/dev/stdin" in args and data is not None:
                stored["value"] = data
            if args[:2] == ["get", "secret"]:
                encoded = base64.b64encode(stored["value"]).decode()
                return json.dumps({"data": {"admin-password": encoded}})
            return ""

        output = io.StringIO()
        with (
            patch.object(lab, "require_vm", return_value=owned_vm()),
            patch.object(lab, "owned_namespace", return_value={}),
            patch.object(lab, "kube", side_effect=kube),
            contextlib.redirect_stdout(output),
        ):
            lab.sync_admin_secret(argparse.Namespace())
        self.assertIn("Updated Secret it-grc-bootstrap", output.getvalue())
        self.assertNotIn(password, output.getvalue())
        self.assertFalse(any(password in " ".join(args) for args, _ in calls))
        self.assertEqual([data for _, data in calls if data], [password.encode()])

    def test_admin_secret_sync_refuses_a_mismatched_secret(self) -> None:
        lab.ensure_private(lab.ADMIN_CREDENTIAL_FILE, lambda: "R" * 32)
        other = json.dumps({"data": {"admin-password": base64.b64encode(b"X" * 32).decode()}})
        with (
            patch.object(lab, "require_vm", return_value=owned_vm()),
            patch.object(lab, "owned_namespace", return_value={}),
            patch.object(lab, "kube", return_value=other),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(lab.GrcLabError),
        ):
            lab.sync_admin_secret(argparse.Namespace())

    def test_failed_command_output_is_redacted(self) -> None:
        lab._SECRETS.add("S" * 40)
        failed = subprocess.CompletedProcess(["x"], 1, b"", b"error near " + b"S" * 40 + b"\n")
        with (
            patch.object(lab.subprocess, "run", return_value=failed),
            self.assertRaises(lab.GrcLabError) as raised,
        ):
            lab.command(["kubectl", "get", "secret"])
        self.assertNotIn("S" * 40, str(raised.exception))
        self.assertIn("<redacted>", str(raised.exception))

    def test_errors_and_private_keys_are_redacted_when_printed(self) -> None:
        lab._SECRETS.add("P" * 40)
        marker = "PRIVATE " + "KEY-----"  # split so the repository scan does not match
        key = f"-----BEGIN {marker}\nsecretbody\n-----END {marker}"
        errors = io.StringIO()
        failure = lab.GrcLabError("bad " + "P" * 40 + " " + key)
        with (
            patch.dict(lab.OPERATIONS, {"status": Mock(side_effect=failure)}),
            contextlib.redirect_stderr(errors),
        ):
            self.assertEqual(lab.main(["status"]), 1)
        self.assertNotIn("P" * 40, errors.getvalue())
        self.assertNotIn("secretbody", errors.getvalue())


class PinTests(OfflineTestCase):
    def test_tracked_pins_are_valid_and_match_the_deploy_files(self) -> None:
        pins = lab.load_pins()
        lab.check_deploy_files(pins)
        self.assertEqual(pins["chart"]["version"], "0.13.3")
        self.assertEqual(
            pins["chart"]["digest"],
            "sha256:b25177e4ce80cf91b2a4b199a4c5bd5c4fb9e2d74bf4e5e39525c4c8dba09343",
        )
        self.assertEqual(
            lab.image_ref(pins["images"]["backend"]),
            "ghcr.io/intuitem/ciso-assistant-community/backend:v4.1.1"
            "@sha256:15f31d4eacd3b60e4c08dca206f608adb6db44fc8a0a1f9ad81bf7edc9f2e410",
        )
        self.assertEqual(
            pins["images"]["frontend"]["digest"],
            "sha256:4a0bd757b9eb5d05555a048f498401d3bde6f8bead554fa12d17fbc099907a7b",
        )

    def test_malformed_or_unpinned_entries_are_refused(self) -> None:
        pins = json.loads(lab.UPSTREAM.read_text())
        broken = []
        for path, value in [
            (("images", "backend", "digest"), "sha256:1234"),
            (("images", "frontend", "tag"), "latest"),
            (("images", "caddy", "registry"), "quay.example"),
            (("chart", "reference"), "oci://ghcr.io/someone/else"),
            (("lima_image", "aarch64", "location"), "http://cloud.debian.org/x.qcow2"),
            (("k3s", "version"), "latest"),
        ]:
            mutated = copy.deepcopy(pins)
            target = mutated
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            broken.append(mutated)
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder)
        for index, mutated in enumerate(broken):
            path = folder / f"{index}.json"
            path.write_text(json.dumps(mutated))
            with self.subTest(index=index), self.assertRaises(lab.GrcLabError):
                lab.load_pins(path)

    def test_deploy_files_must_use_exactly_the_pins(self) -> None:
        pins = lab.load_pins()
        changed = copy.deepcopy(pins)
        changed["images"]["backend"]["digest"] = "sha256:" + "1" * 64
        with self.assertRaises(lab.GrcLabError):
            lab.check_deploy_files(changed)
        changed = copy.deepcopy(pins)
        changed["k3s"]["aarch64"]["sha256"] = "2" * 64
        with self.assertRaises(lab.GrcLabError):
            lab.check_deploy_files(changed)
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder)
        extra = folder / "values.yaml"
        extra.write_text(lab.VALUES.read_text() + "x:\n  image: a/b@sha256:" + "3" * 64 + "\n")
        with patch.object(lab, "VALUES", extra), self.assertRaises(lab.GrcLabError):
            lab.check_deploy_files(pins)

    def test_registry_mismatch_is_refused(self) -> None:
        body = b'{"schemaVersion": 2}'
        image = {
            "registry": "ghcr.io",
            "repository": "example/app",
            "tag": "v1",
            "digest": lab.digest_of(body),
        }
        with patch.object(lab, "registry_get", return_value=(body, image["digest"])):
            lab.verify_image(image)
        other = "sha256:" + "4" * 64
        for answer in [(body, other), (b"tampered", image["digest"])]:
            with (
                self.subTest(answer=answer[1]),
                patch.object(lab, "registry_get", return_value=answer),
                self.assertRaises(lab.GrcLabError),
            ):
                lab.verify_image(image)

    def test_chart_content_layer_must_match_the_pin(self) -> None:
        chart = lab.load_pins()["chart"]
        manifest = {"layers": [{"mediaType": lab.CHART_LAYER, "digest": "sha256:" + "5" * 64}]}
        with (
            patch.object(lab, "verify_image"),
            patch.object(lab, "registry_get", return_value=(json.dumps(manifest).encode(), "")),
            self.assertRaises(lab.GrcLabError),
        ):
            lab.chart_manifest(chart)

    def test_only_https_sources_are_fetched(self) -> None:
        with self.assertRaises(lab.GrcLabError):
            lab.fetch("http://ghcr.io/v2/")


class ProfileTests(OfflineTestCase):
    def test_cluster_objects_are_owned_restricted_and_pinned(self) -> None:
        pins = lab.load_pins()
        cluster = lab.cluster_manifests()
        namespace = cluster[0]["metadata"]["labels"]
        self.assertEqual(namespace[lab.OWNER_KEY], lab.OWNER_VALUE)
        self.assertEqual(namespace["pod-security.kubernetes.io/enforce"], "restricted")
        items = {
            (row["kind"], row["metadata"]["name"]): row for row in lab.namespace_manifests(pins)
        }
        self.assertFalse(items[("ServiceAccount", "default")]["automountServiceAccountToken"])
        policy = items[("NetworkPolicy", "it-grc-namespace-only")]["spec"]
        self.assertEqual(policy["podSelector"], {})
        self.assertEqual(policy["ingress"], [{"from": [{"podSelector": {}}]}])
        pod = items[("Deployment", "it-grc-tls")]["spec"]["template"]["spec"]
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        self.assertNotIn("hostNetwork", pod)
        container = pod["containers"][0]
        self.assertNotIn("hostPort", container["ports"][0])
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertIn("@sha256:", container["image"])
        for row in cluster[1:]:
            self.assertEqual(row["spec"]["persistentVolumeReclaimPolicy"], "Retain")

    def test_tracked_profile_and_values_keep_the_boundaries(self) -> None:
        profile = lab.PROFILE.read_text()
        for line in (
            "mounts: []",
            "forwardAgent: false",
            "loadDotSSHPubKeys: false",
            "owner: it-grc",
            "ignore: true",
        ):
            self.assertIn(line, profile)
        values = lab.VALUES.read_text()
        self.assertIn('emailAdmin: ""', values)
        self.assertIn("automountServiceAccountToken: false", values)
        self.assertIn("name: it-grc-bootstrap", values)
        inline = re.search(r"(?im)^\s*(password|djangoSecretKey|privateKey)\s*:", values)
        self.assertIsNone(inline)


if __name__ == "__main__":
    unittest.main()
