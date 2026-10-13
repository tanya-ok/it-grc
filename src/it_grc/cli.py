"""Command line for the CISO Assistant bridge. Every command needs a repository checkout."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from . import __version__, grc_ledger, grc_ops, grc_push


def repository() -> Path:
    """The checkout that holds deploy/.data, the mapping and scripts/grc_lab.py."""
    if override := os.environ.get("IT_GRC_ROOT"):
        return Path(override)
    return Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="it-grc",
        description="Push executed security-lab evidence into CISO Assistant CE and verify it",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("command", choices=[*grc_ops.OPERATIONS, *grc_push.OPERATIONS, "ledger"])
    parser.add_argument(
        "action", nargs="?", choices=["verify"], help="ledger: check the local push ledger"
    )
    parser.add_argument("--report", type=Path, help="push: the lab report JSON file")
    parser.add_argument(
        "--dry-run", action="store_true", help="push: list the planned changes, write nothing"
    )
    args = parser.parse_args()
    if (args.command == "ledger") != (args.action is not None):
        parser.error("use `ledger verify`; other commands take no action")
    if args.command == "push" and args.report is None:
        parser.error("push needs --report <path>")
    root = repository()
    if args.command == "ledger":
        raise SystemExit(grc_ops.run("ledger-verify", root, operations=grc_ledger.OPERATIONS))
    operations = {**grc_ops.OPERATIONS, **grc_push.OPERATIONS}
    raise SystemExit(
        grc_ops.run(
            args.command, root, operations=operations, report=args.report, dry_run=args.dry_run
        )
    )
