"""Check public references, links and repository source hygiene offline."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IGNORED = {
    ".git",
    ".data",
    ".venv",
    "__pycache__",
    ".ruff_cache",
    ".mypy_cache",
    ".venv-docs",
    "site",
    ".cache",
}


class RepositoryCheckError(Exception):
    pass


def require(condition: bool, message: object) -> None:
    if not condition:
        raise RepositoryCheckError(str(message))


def main() -> None:
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in IGNORED for part in path.relative_to(ROOT).parts):
            continue
        if path.suffix not in {
            ".json",
            ".md",
            ".py",
            ".js",
            ".css",
            ".html",
            ".toml",
            ".yaml",
            ".yml",
        }:
            continue
        text = path.read_text()
        require("\u2014" not in text and "\u2013" not in text, f"long dash in {path}")
        require(
            not re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", text),
            f"private key header in {path}",
        )
        if path.suffix == ".json":
            json.loads(text)
        if path.suffix == ".md":
            for link in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
                if "://" not in link and not link.startswith("#"):
                    require(
                        (path.parent / link.split("#")[0]).exists(),
                        f"broken link {link} in {path}",
                    )
    sources = json.loads((ROOT / "references/sources.json").read_text())["sources"]
    ids = {source["id"] for source in sources}
    require(len(ids) == len(sources), "duplicate source ids")
    for source in sources:
        require(source["url"].startswith("https://www.hhs.gov/"), f"non-HHS source {source['id']}")
        require(
            source["reference_checked_on"] == "2026-10-06",
            f"unexpected reference date for {source['id']}",
        )
    print("Repository references, links and source hygiene passed.")


if __name__ == "__main__":
    try:
        main()
    except RepositoryCheckError as error:
        raise SystemExit("Repository check failed: " + str(error)) from None
