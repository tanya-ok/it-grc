"""Check the mapping against the pinned upstream NIST SP 800-66 rev2 library YAML.

The library file belongs to CISO Assistant Community edition (AGPL-3.0-or-later) and is never
stored in this repository. `--download` reads it into memory from the commit pinned in
deploy/upstream.json; a local path is accepted for offline checks. Standard library only: the
reader understands the YAML subset the library uses for its requirement nodes and refuses any
construct it would have to interpret beyond that.

The contract:

- the file has the pinned SHA-256, library URN and framework URN;
- the framework holds the pinned number of requirement nodes and assessable nodes;
- every URN in mappings/hipaa-800-66r2.json exists once, is assessable at depth 3 and has the
  name and parent section recorded in the mapping.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import sys
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
UPSTREAM = ROOT / "deploy/upstream.json"
MAPPING = ROOT / "mappings/hipaa-800-66r2.json"
MAX_BYTES = 8 * 1024 * 1024
SOURCE = re.compile(
    r"https://raw\.githubusercontent\.com/intuitem/ciso-assistant-community/([0-9a-f]{40})"
    r"/backend/library/libraries/[a-z0-9.-]{1,80}\.yaml"
)
HEX64 = re.compile(r"[0-9a-f]{64}")
KEY = re.compile(r"([a-z_]{1,60}):(?: (.*))?")
ESCAPES = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "\t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\x85",
    "_": "\xa0",
    "L": chr(0x2028),
    "P": chr(0x2029),
}
HEX_ESCAPES = {"x": 2, "u": 4, "U": 8}
ASSESSABLE_DEPTH = 3


class ContractError(Exception):
    """The library or the mapping breaks the contract. Fixed text plus URNs and digests."""


def require(condition: object, message: str) -> None:
    if not condition:
        raise ContractError(message)


@dataclass(frozen=True)
class Node:
    urn: str
    assessable: bool
    depth: int
    parent_urn: str | None
    name: str | None


@dataclass(frozen=True)
class Library:
    urn: str
    framework_urn: str
    nodes: dict[str, Node]


# YAML subset reader


def indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


Entry = tuple[int, int, str]


def entries(lines: Sequence[str], start: int, end: int, indent: int) -> dict[str, Entry]:
    """Keys at exactly `indent` in lines[start:end]: key -> (line, end line, inline value).

    A key's block runs to the next line at `indent` or less, except the `- ` entries of a
    sequence written at the key's own indentation, which belong to a key without a value."""
    found: dict[str, Entry] = {}
    index = start
    while index < end:
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        match = KEY.fullmatch(line[indent:]) if indentation(line) == indent else None
        if match is None:
            raise ContractError(f"line {index + 1}: unsupported YAML structure")
        key, value = match.group(1), match.group(2) or ""
        require(key not in found, f"line {index + 1}: duplicate key {key}")
        stop = index + 1
        while stop < end:
            following = lines[stop]
            if following.strip() and indentation(following) <= indent:
                in_sequence = indentation(following) == indent and following[indent:][:2] == "- "
                if not (in_sequence and not value):
                    break
            stop += 1
        found[key] = (index, stop, value)
        index = stop
    return found


def fold(lines: Sequence[str]) -> str:
    """YAML line folding: one line break becomes a space, each empty line a line feed."""
    text, pending = "", 0
    for index, line in enumerate(lines):
        if index == 0:
            text = line
        elif not line:
            pending += 1
        else:
            text += "\n" * pending if pending else " "
            text += line
            pending = 0
    return text


def plain(parts: Sequence[str]) -> str:
    lines = [part.strip() for part in parts]
    require(not any(" #" in line or ": " in line for line in lines), "unsupported plain scalar")
    return fold(lines)


def quoted(raw: str, quote: str) -> str:
    """A single- or double-quoted flow scalar spread over lines joined by line feeds."""
    require(raw.startswith(quote), "unsupported quoted scalar")
    out: list[str] = []
    protected = 0
    index = 1
    while index < len(raw):
        char = raw[index]
        if char == quote:
            if quote == "'" and raw[index + 1 : index + 2] == "'":
                out.append("'")
                protected = len(out)
                index += 2
                continue
            require(not raw[index + 1 :].strip(), "text after a closing quote")
            return "".join(out)
        if char == "\\" and quote == '"':
            index, protected = escape(raw, index, out)
            continue
        if char == "\n":
            while len(out) > protected and out[-1] in " \t":
                out.pop()
            breaks = 0
            while index < len(raw) and raw[index] in " \t\n":
                breaks += raw[index] == "\n"
                index += 1
            out.append("\n" * (breaks - 1) if breaks > 1 else " ")
            continue
        out.append(char)
        index += 1
    raise ContractError("unterminated quoted scalar")


def escape(raw: str, index: int, out: list[str]) -> tuple[int, int]:
    """One escape sequence at raw[index] (a backslash). Returns the next index and the new
    protected length of `out`, so escaped white space survives line folding."""
    code = raw[index + 1 : index + 2]
    if code == "\n":
        index += 2
        while index < len(raw) and raw[index] in " \t":
            index += 1
        return index, len(out)
    if code in ESCAPES:
        out.append(ESCAPES[code])
        return index + 2, len(out)
    width = HEX_ESCAPES.get(code)
    digits = raw[index + 2 : index + 2 + width] if width else ""
    require(width and re.fullmatch(r"[0-9A-Fa-f]+", digits) and len(digits) == width, "bad escape")
    out.append(chr(int(digits, 16)))
    return index + 2 + len(digits), len(out)


def scalar(lines: Sequence[str], entry: Entry) -> str:
    first, stop, value = entry
    parts = [value, *lines[first + 1 : stop]]
    while len(parts) > 1 and not parts[-1].strip():
        parts.pop()
    head = value.lstrip()
    require(head, f"line {first + 1}: expected a value")
    require(head[0] not in "|>&*!%@`[{", f"line {first + 1}: unsupported scalar style")
    if head[0] in "\"'":
        # Indentation and unescaped white space around line breaks are folded by `quoted`.
        return quoted("\n".join([head, *parts[1:]]), head[0])
    return plain(parts)


def parse_library(text: str) -> Library:
    require("\t" not in text and "\r" not in text, "tabs and carriage returns are not supported")
    lines = text.split("\n")
    top = entries(lines, 0, len(lines), 0)
    require("urn" in top and "objects" in top, "the file is not a library")
    objects = entries(lines, top["objects"][0] + 1, top["objects"][1], 2)
    require("framework" in objects, "the library holds no framework")
    framework = entries(lines, objects["framework"][0] + 1, objects["framework"][1], 4)
    require("requirement_nodes" in framework, "the framework holds no requirement nodes")
    start, end, _ = framework["requirement_nodes"]
    nodes: dict[str, Node] = {}
    index = start + 1
    while index < end:
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        require(line.startswith("    - "), f"line {index + 1}: expected a requirement node")
        stop = index + 1
        while stop < end and (not lines[stop].strip() or indentation(lines[stop]) > 4):
            stop += 1
        # The entry's first key follows "- "; shift it to the indentation of its other keys.
        block = ["      " + line[6:], *lines[index + 1 : stop]]
        node = read_node(block, index)
        require(node.urn not in nodes, f"duplicate requirement node {node.urn}")
        nodes[node.urn] = node
        index = stop
    return Library(
        scalar(lines, top["urn"]),
        scalar(lines, framework["urn"]) if "urn" in framework else "",
        nodes,
    )


def read_node(block: Sequence[str], line: int) -> Node:
    fields = entries(block, 0, len(block), 6)
    require({"urn", "assessable", "depth"} <= set(fields), f"line {line + 1}: incomplete node")
    assessable = scalar(block, fields["assessable"])
    depth = scalar(block, fields["depth"])
    require(assessable in {"true", "false"}, f"line {line + 1}: assessable is not a boolean")
    require(re.fullmatch(r"[0-9]{1,2}", depth), f"line {line + 1}: depth is not a number")
    return Node(
        urn=scalar(block, fields["urn"]),
        assessable=assessable == "true",
        depth=int(depth),
        parent_urn=scalar(block, fields["parent_urn"]) if "parent_urn" in fields else None,
        name=scalar(block, fields["name"]) if "name" in fields else None,
    )


# Contract


def load_pin(path: Path = UPSTREAM) -> dict[str, Any]:
    try:
        pin: dict[str, Any] = json.loads(path.read_text())["library"]
        source = SOURCE.fullmatch(pin["source"])
        require(source and source.group(1) == pin["commit"], "library source is not pinned")
        require(HEX64.fullmatch(pin["sha256"]), "library sha256")
        for key in ("requirement_nodes", "assessable_nodes"):
            require(type(pin[key]) is int and pin[key] > 0, f"library {key}")
        for key in ("urn", "framework_urn"):
            require(isinstance(pin[key], str), f"library {key}")
    except (OSError, ValueError, KeyError, TypeError):
        raise ContractError("deploy/upstream.json has no valid library pin") from None
    return pin


def mapped_targets(path: Path = MAPPING) -> tuple[str, list[tuple[str, str, str]]]:
    """The framework URN and every mapped (urn, name, section) of the mapping file."""
    try:
        mapping = json.loads(path.read_text())
        rows = [*mapping["requirements"]]
        rows += [node for gap in mapping["not_verified"] for node in gap["nodes"]]
        targets = [(row["urn"], row["name"], row["section"]) for row in rows]
        framework = mapping["framework"]
    except (OSError, ValueError, KeyError, TypeError):
        raise ContractError("mappings/hipaa-800-66r2.json cannot be read") from None
    require(all(isinstance(value, str) for row in targets for value in row), "mapping has non-text")
    require(isinstance(framework, str), "mapping framework")
    return framework, targets


def check(data: bytes, pin: dict[str, Any], mapping: Path = MAPPING) -> list[str]:
    """Report lines for a library that meets the contract; raises ContractError otherwise."""
    digest = hashlib.sha256(data).hexdigest()
    require(digest == pin["sha256"], f"library sha256 {digest} differs from the pin")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ContractError("the library is not UTF-8") from None
    library = parse_library(text)
    framework, targets = mapped_targets(mapping)
    require(library.urn == pin["urn"], "library URN differs from the pin")
    require(
        library.framework_urn == pin["framework_urn"] == framework,
        "framework URN differs from the pin or the mapping",
    )
    assessable = [node for node in library.nodes.values() if node.assessable]
    require(
        (len(library.nodes), len(assessable))
        == (pin["requirement_nodes"], pin["assessable_nodes"]),
        f"library holds {len(library.nodes)} nodes, {len(assessable)} assessable; the pin says"
        f" {pin['requirement_nodes']} and {pin['assessable_nodes']}",
    )
    problems: list[str] = []
    for urn, name, section in targets:
        node = library.nodes.get(urn)
        if node is None:
            problems.append(f"{urn} is not in the library")
            continue
        if not node.assessable or node.depth != ASSESSABLE_DEPTH:
            problems.append(f"{urn} is not assessable at depth {ASSESSABLE_DEPTH}")
        if node.name != name:
            problems.append(f"{urn} name differs from the mapping")
        if (node.parent_urn or "").rsplit(":", 1)[-1] != section:
            problems.append(f"{urn} parent section differs from the mapping")
    require(not problems, "; ".join(problems))
    return [
        f"PASS library sha256 {digest} matches the pin (commit {pin['commit']})",
        f"PASS {library.urn}: {len(library.nodes)} requirement nodes, {len(assessable)} assessable",
        f"PASS {len(targets)} mapped URNs exist, are assessable at depth {ASSESSABLE_DEPTH} and"
        " carry the mapped name and section",
        f"{len(assessable) - len(targets)} assessable nodes are not in the mapping",
    ]


def download(url: str) -> bytes:
    """The pinned file, read into memory over verified HTTPS and never written to disk."""
    require(SOURCE.fullmatch(url), "refusing a library source that is not pinned to a commit")
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(url, timeout=60, context=context) as response:
            data: bytes = response.read(MAX_BYTES + 1)
    except OSError:
        raise ContractError("the pinned library could not be downloaded") from None
    require(len(data) <= MAX_BYTES, "the library exceeds the size limit")
    return data


def read_local(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_BYTES + 1)
    except OSError:
        raise ContractError("the library file cannot be read") from None
    require(len(data) <= MAX_BYTES, "the library exceeds the size limit")
    return data


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0] if __doc__ else None)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--download", action="store_true", help="read the pinned file over HTTPS into memory"
    )
    source.add_argument("path", nargs="?", type=Path, help="a local copy of the library file")
    args = parser.parse_args(argv)
    try:
        pin = load_pin()
        data = download(pin["source"]) if args.download else read_local(args.path)
        for line in check(data, pin):
            print(line)
    except ContractError as error:
        print(f"Mapping contract failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
