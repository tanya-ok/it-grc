"""Local append-only ledger of bridge pushes, chained by SHA-256.

Every push that sends a write appends one JSON line to deploy/.data/grc-ledger.jsonl. A line
is the canonical JSON of its record (`json-sort-keys-compact-ascii-v1`), and `record_hash` is
the SHA-256 of that canonical JSON without `record_hash` itself, so it covers `prev_hash`, the
hash of the line before. An edited, reordered or deleted record breaks the chain.

The chain alone cannot see a truncated tail. deploy/.data/grc-ledger.checkpoint holds the
record count and the last record hash and is replaced after each append, so verify detects a
removed tail as well. Neither file is signed: whoever can rewrite both files can rewrite the
history. The files show accidental or partial tampering, not a determined local attacker.

Records hold ids, hashes, versions and results. A record that contains a secret the run knows
is refused before it is written.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .grc_ops import OpsError, Redactor, Say, Settings, Vault
from .lab_report import InvalidEvidence, canonical_record, unique_object

LEDGER_FILE = "grc-ledger.jsonl"
CHECKPOINT_FILE = "grc-ledger.checkpoint"
GENESIS = "0" * 64
RECORD_KIND = "it-grc-ledger-record"
CHECKPOINT_KIND = "it-grc-ledger-checkpoint"
FORMAT = 1
CHAIN_FIELDS = frozenset({"kind", "format", "seq", "prev_hash", "record_hash"})
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_CHECKPOINT_BYTES = 4096
HEX64 = re.compile(r"[0-9a-f]{64}")


class LedgerError(OpsError):
    """The ledger or its checkpoint failed a check. Fixed text, never file content."""


def canonical(value: Mapping[str, Any]) -> bytes:
    try:
        return canonical_record(dict(value))
    except InvalidEvidence:
        raise LedgerError("A ledger record cannot be written as canonical JSON") from None


def chain_hash(record: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical JSON of the record without `record_hash`."""
    body = {key: value for key, value in record.items() if key != "record_hash"}
    return hashlib.sha256(canonical(body)).hexdigest()


@dataclass(frozen=True)
class LedgerState:
    records: tuple[dict[str, Any], ...]
    checkpoint: int | None
    warnings: tuple[str, ...]

    @property
    def head(self) -> str:
        return str(self.records[-1]["record_hash"]) if self.records else GENESIS


def shown(name: str) -> str:
    return f"deploy/.data/{name}"


def _owner_only(descriptor: int, name: str) -> None:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise LedgerError(f"Refusing {shown(name)}: it must be an owner-only (0600) regular file")


def _open(path: Path, flags: int) -> int:
    try:
        descriptor = os.open(path, flags | os.O_NOFOLLOW, 0o600)
    except FileNotFoundError:
        raise
    except OSError:
        raise LedgerError(f"Refusing {shown(path.name)}: it cannot be opened safely") from None
    try:
        _owner_only(descriptor, path.name)
    except LedgerError:
        os.close(descriptor)
        raise
    return descriptor


def _lock(descriptor: int, *, exclusive: bool) -> None:
    """An advisory lock held until the descriptor is closed. POSIX only, like the bridge."""
    import fcntl  # noqa: PLC0415 - keeps the package importable where fcntl does not exist

    fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)


def _read_all(descriptor: int, limit: int, name: str) -> bytes:
    data = b""
    while chunk := os.pread(descriptor, 1024 * 1024, len(data)):
        data += chunk
        if len(data) > limit:
            raise LedgerError(f"{shown(name)} exceeds {limit} bytes")
    return data


def parse_records(raw: bytes) -> list[dict[str, Any]]:
    """Every record, checked from the genesis hash to the last line."""
    if not raw:
        return []
    if not raw.endswith(b"\n"):
        raise LedgerError("Ledger check failed: the last line is incomplete")
    records: list[dict[str, Any]] = []
    previous = GENESIS
    for index, line in enumerate(raw[:-1].split(b"\n"), start=1):
        failed = f"Ledger check failed: record {index}"
        if len(line) > MAX_RECORD_BYTES:
            raise LedgerError(f"{failed} is too large")
        try:
            record = json.loads(line, object_pairs_hook=unique_object)
        except (ValueError, InvalidEvidence, RecursionError):
            raise LedgerError(f"{failed} is not valid JSON") from None
        if (
            not isinstance(record, dict)
            or record.get("kind") != RECORD_KIND
            or record.get("format") != FORMAT
        ):
            raise LedgerError(f"{failed} is not a ledger record")
        if canonical(record) != line:
            raise LedgerError(f"{failed} is not in canonical form; it was edited")
        if record.get("seq") != index:
            raise LedgerError(
                f"{failed} has the wrong sequence number; records were removed or reordered"
            )
        if record.get("prev_hash") != previous:
            raise LedgerError(
                f"{failed} does not chain to the record before it; a record was edited,"
                " removed or reordered"
            )
        stated = record.get("record_hash")
        if not isinstance(stated, str) or not HEX64.fullmatch(stated):
            raise LedgerError(f"{failed} has no valid record_hash")
        if chain_hash(record) != stated:
            raise LedgerError(f"{failed} does not match its record_hash; it was edited")
        previous = stated
        records.append(record)
    return records


def read_checkpoint(folder: Path) -> tuple[int, str] | None:
    try:
        descriptor = _open(folder / CHECKPOINT_FILE, os.O_RDONLY)
    except FileNotFoundError:
        return None
    try:
        raw = _read_all(descriptor, MAX_CHECKPOINT_BYTES, CHECKPOINT_FILE)
    finally:
        os.close(descriptor)
    refused = f"Ledger check failed: {shown(CHECKPOINT_FILE)} is malformed"
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, InvalidEvidence, RecursionError):
        raise LedgerError(refused) from None
    if (
        not isinstance(value, dict)
        or set(value) != {"kind", "format", "count", "record_hash"}
        or value["kind"] != CHECKPOINT_KIND
        or value["format"] != FORMAT
        or type(value["count"]) is not int
        or value["count"] < 1
        or not isinstance(value["record_hash"], str)
        or not HEX64.fullmatch(value["record_hash"])
        or canonical(value) + b"\n" != raw
    ):
        raise LedgerError(refused)
    return value["count"], value["record_hash"]


def check_checkpoint(
    records: list[dict[str, Any]], checkpoint: tuple[int, str] | None
) -> list[str]:
    """Fails when the checkpoint shows removed records. Returns warnings."""
    if checkpoint is None:
        if records:
            raise LedgerError(
                f"Ledger check failed: the ledger holds {len(records)} record(s) but"
                f" {shown(CHECKPOINT_FILE)} is missing"
            )
        return []
    count, head = checkpoint
    if len(records) < count:
        raise LedgerError(
            f"Ledger check failed: the ledger holds {len(records)} record(s) and the checkpoint"
            f" {count}; records were removed from the end"
        )
    if records[count - 1]["record_hash"] != head:
        raise LedgerError(
            f"Ledger check failed: record {count} does not match the checkpoint; the ledger"
            " was rewritten"
        )
    if len(records) > count:
        return [
            f"the checkpoint covers {count} of {len(records)} records; the last append did not"
            " update it, so removal of the records after it would not be detected"
        ]
    return []


def verify_ledger(folder: Path) -> LedgerState:
    """Read and check the chain and the checkpoint. Raises LedgerError on any failure."""
    try:
        descriptor = _open(folder / LEDGER_FILE, os.O_RDONLY)
    except FileNotFoundError:
        raw = b""
        checkpoint = read_checkpoint(folder)
    else:
        try:
            _lock(descriptor, exclusive=False)
            raw = _read_all(descriptor, MAX_LEDGER_BYTES, LEDGER_FILE)
            checkpoint = read_checkpoint(folder)
        finally:
            os.close(descriptor)
    records = parse_records(raw)
    warnings = check_checkpoint(records, checkpoint)
    return LedgerState(tuple(records), checkpoint[0] if checkpoint else None, tuple(warnings))


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]
    os.fsync(descriptor)


def write_checkpoint(folder: Path, count: int, record_hash: str) -> None:
    content = (
        canonical(
            {"kind": CHECKPOINT_KIND, "format": FORMAT, "count": count, "record_hash": record_hash}
        )
        + b"\n"
    )
    temporary = folder / (CHECKPOINT_FILE + ".tmp")
    temporary.unlink(missing_ok=True)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        _write_all(descriptor, content)
    finally:
        os.close(descriptor)
    temporary.replace(folder / CHECKPOINT_FILE)
    directory = os.open(folder, os.O_RDONLY)
    try:
        with contextlib.suppress(OSError):
            os.fsync(directory)
    finally:
        os.close(directory)


def append(folder: Path, body: Mapping[str, Any], redactor: Redactor) -> dict[str, Any]:
    """Append one record after checking the existing chain and checkpoint, under a lock."""
    if CHAIN_FIELDS & set(body):
        raise LedgerError("A ledger record body must not set the chain fields")
    if folder.is_symlink() or not folder.is_dir():
        raise LedgerError("deploy/.data must be a directory")
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT
    descriptor = _open(folder / LEDGER_FILE, flags)
    try:
        _lock(descriptor, exclusive=True)
        records = parse_records(_read_all(descriptor, MAX_LEDGER_BYTES, LEDGER_FILE))
        check_checkpoint(records, read_checkpoint(folder))
        previous = str(records[-1]["record_hash"]) if records else GENESIS
        record = {
            **body,
            "kind": RECORD_KIND,
            "format": FORMAT,
            "seq": len(records) + 1,
            "prev_hash": previous,
        }
        record["record_hash"] = chain_hash(record)
        line = canonical(record) + b"\n"
        text = line.decode("ascii")
        if redactor(text) != text:
            raise LedgerError("Refusing to write a ledger record that contains a secret")
        _write_all(descriptor, line)
        write_checkpoint(folder, int(record["seq"]), str(record["record_hash"]))
    finally:
        os.close(descriptor)
    return record


def latest_complete(
    records: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """The last record of a complete push, and the failed records after it."""
    later: list[dict[str, Any]] = []
    for record in reversed(records):
        if record.get("outcome") == "complete":
            return record, list(reversed(later))
        later.append(record)
    return None, list(reversed(later))


def data_folder(settings: Settings, redactor: Redactor) -> Path:
    return Vault(settings.data, redactor).directory()


def ledger_verify(settings: Settings, say: Say, redactor: Redactor) -> LedgerState:
    """`it-grc ledger verify`: offline check of the chain and the checkpoint."""
    state = verify_ledger(data_folder(settings, redactor))
    for warning in state.warnings:
        say(f"WARNING {warning}")
    if not state.records:
        say(f"PASS ledger: {shown(LEDGER_FILE)} holds no records yet")
        return state
    last = state.records[-1]
    count = len(state.records)
    say(f"PASS ledger: {count} record(s), each chained to the one before it from the genesis hash")
    say(f"PASS checkpoint: record {state.checkpoint} matches {shown(CHECKPOINT_FILE)}")
    say(
        f"Last record: seq {last['seq']}, {last.get('time')}, outcome {last.get('outcome')},"
        f" record_hash {last['record_hash']}"
    )
    return state


OPERATIONS: dict[str, Callable[[Settings, Say, Redactor], object]] = {
    "ledger-verify": ledger_verify,
}


__all__ = [
    "CHECKPOINT_FILE",
    "LEDGER_FILE",
    "OPERATIONS",
    "LedgerError",
    "LedgerState",
    "append",
    "latest_complete",
    "verify_ledger",
]
