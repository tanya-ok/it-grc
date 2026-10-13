"""The command line offers only the bridge commands. No CISO Assistant, no network."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from it_grc import __version__

ROOT = Path(__file__).resolve().parent.parent


def run_cli(*args: str, root: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    if root is not None:
        env["IT_GRC_ROOT"] = str(root)
    return subprocess.run(
        [sys.executable, "-m", "it_grc", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )


class CommandLineTests(unittest.TestCase):
    def test_version_is_the_package_version(self) -> None:
        done = run_cli("--version")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), f"it-grc {__version__}")

    def test_the_latest_changelog_entry_is_the_package_version(self) -> None:
        text = (ROOT / "CHANGELOG.md").read_text()
        latest = re.search(r"^## \[([0-9]+\.[0-9]+\.[0-9]+)\]", text, re.MULTILINE)
        assert latest is not None
        self.assertEqual(latest.group(1), __version__)

    def test_prototype_commands_are_gone(self) -> None:
        for command in (
            "serve",
            "demo",
            "assess",
            "evaluate",
            "import-lab",
            "backup-state",
            "restore-state",
        ):
            with self.subTest(command=command):
                done = run_cli(command)
                self.assertEqual(done.returncode, 2)
                self.assertIn("invalid choice", done.stderr)

    def test_bridge_commands_need_a_repository_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            for command in ("summary", "verify", "bridge-check"):
                with self.subTest(command=command):
                    done = run_cli(command, root=Path(folder))
                    self.assertEqual(done.returncode, 2)
                    self.assertIn("need a repository checkout", done.stderr)
            done = run_cli("push", root=Path(folder))
            self.assertEqual(done.returncode, 2)
            self.assertIn("push needs --report", done.stderr)

    def test_demo_target_runs_the_documented_sequence_on_the_fixture(self) -> None:
        text = (ROOT / "Makefile").read_text()
        recipe = text.split("\ngrc-demo:\n", 1)[1].split("\n\n", 1)[0]
        steps = [
            line.split("-m it_grc ", 1)[1] for line in recipe.splitlines() if "-m it_grc" in line
        ]
        self.assertEqual(
            steps,
            [
                'push --report "$(REPORT)" --dry-run',
                'push --report "$(REPORT)"',
                "verify",
                "ledger verify",
                "summary",
            ],
        )
        default = re.search(r"^REPORT \?= (\S+)$", text, re.MULTILINE)
        assert default is not None
        self.assertTrue((ROOT / default.group(1)).is_file())


if __name__ == "__main__":
    unittest.main()
