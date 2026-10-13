from __future__ import annotations

import ast
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ["validate_repository.py", "grc_lab.py", "check_mapping_contract.py"]


class RepositoryValidatorTests(unittest.TestCase):
    def test_scripts_do_not_rely_on_assert_statements(self) -> None:
        for name in SCRIPTS:
            tree = ast.parse((ROOT / "scripts" / name).read_text())
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)), name)

    def test_violations_fail_even_with_optimizations_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "scripts").mkdir()
            shutil.copy(ROOT / "scripts/validate_repository.py", root / "scripts")
            shutil.copytree(ROOT / "references", root / "references")
            (root / "note.md").write_text(
                "Synthetic text with a long dash " + chr(0x2014) + " here.\n"
            )
            result = subprocess.run(
                [sys.executable, "-O", str(root / "scripts/validate_repository.py")],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("long dash", result.stderr)
            (root / "note.md").write_text("Synthetic text.\n")
            result = subprocess.run(
                [sys.executable, "-O", str(root / "scripts/validate_repository.py")],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
