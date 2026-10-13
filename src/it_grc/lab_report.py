"""Strict validator for executed security-lab reports.

`import_lab` accepts only the 18-scenario report of the shared security lab, keeps its
validated fields and records two digests: the SHA-256 of the raw file bytes and the SHA-256
of the canonical record (`json-sort-keys-compact-ascii-v1`). Free text in the report is
never kept. A report is untrusted input; nothing in it can change what the bridge does.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_BYTES = 1_048_576
BACKEND = "lima-kubernetes-containerd"
RECORD_FORMAT = "json-sort-keys-compact-ascii-v1"
PRODUCERS = frozenset({"mcp-svid-auth", "hipaa-fhir-mcp", "mcp-spiffe-bridge"})
COMMIT = re.compile(r"[a-f0-9]{40}")
SCENARIOS = {
    1: "Allowlisted access",
    2: "Tool scope denial",
    3: "Unlisted identity denial",
    4: "Cross-resource replay denial",
    5: "ServiceAccount attestation",
    6: "Untrusted issuer refusal",
    7: "Explicit assertion reuse mode",
    8: "Own identity for upstream calls",
    9: "Grant removal",
    10: "Identity and intent limits",
    11: "Signing key restart",
    12: "SVID renewal and expiry",
    13: "Strict assertion replay",
    14: "Audit checkpoint verification",
    15: "FHIR authentication and authorization",
    16: "Disallowed mTLS identity",
    17: "Missing mTLS certificate",
    18: "Safe FHIR audit",
}


class InvalidEvidence(ValueError):
    """Fixed public errors without untrusted input or exception text."""


def now() -> str:
    return datetime.now(UTC).isoformat()


def read_json_artifact(path: Path, *, max_bytes: int = MAX_BYTES) -> tuple[dict[str, Any], bytes]:
    """A bounded JSON object without duplicate keys, and the exact bytes it was read from."""
    with path.open("rb") as stream:
        artifact = stream.read(max_bytes + 1)
    if len(artifact) > max_bytes:
        raise InvalidEvidence("evidence_too_large")
    try:
        value = json.loads(artifact, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise InvalidEvidence("invalid_json") from None
    if not isinstance(value, dict):
        raise InvalidEvidence("invalid_document")
    return value, artifact


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidEvidence("duplicate_json_key")
        result[key] = value
    return result


def utc_timestamp(value: Any) -> str:
    try:
        if not isinstance(value, str) or len(value) > 40:
            raise ValueError
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset() is None or parsed > datetime.now(UTC):
            raise ValueError
        return parsed.astimezone(UTC).isoformat()
    except ValueError:
        raise InvalidEvidence("invalid_capture_time") from None


def boolean(value: Any) -> bool:
    if type(value) is not bool:
        raise InvalidEvidence("invalid_boolean")
    return bool(value)


def canonical_record(raw: dict[str, Any]) -> bytes:
    """Versioned project JSON format, not RFC 8785 or raw-file identity."""
    try:
        return json.dumps(
            raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise InvalidEvidence("invalid_json_record") from None


def scenario_outcomes(results: Any) -> dict[int, bool]:
    if not isinstance(results, list) or len(results) != len(SCENARIOS):
        raise InvalidEvidence("incomplete_lab_report")
    records: dict[int, bool] = {}
    for row in results:
        if not isinstance(row, dict):
            raise InvalidEvidence("invalid_scenario")
        number = row.get("scenario")
        if type(number) is not int or number not in SCENARIOS or number in records:
            raise InvalidEvidence("invalid_scenario")
        records[number] = boolean(row.get("passed"))
    return records


def producer_revisions(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - PRODUCERS:
        raise InvalidEvidence("invalid_lab_revision")
    for item in value.values():
        if (
            not isinstance(item, dict)
            or set(item) != {"revision", "dirty"}
            or not isinstance(item["revision"], str)
            or COMMIT.fullmatch(item["revision"]) is None
        ):
            raise InvalidEvidence("invalid_lab_revision")
        boolean(item["dirty"])
    return value


def import_lab(raw: dict[str, Any], artifact: bytes) -> dict[str, Any]:
    """The validated summary of one lab report; `artifact` holds its raw file bytes."""
    if len(artifact) > MAX_BYTES or raw.get("backend") != BACKEND:
        raise InvalidEvidence("unsupported_lab_report")
    normalized = canonical_record(raw)
    if len(normalized) > MAX_BYTES:
        raise InvalidEvidence("unsupported_lab_report")
    captured = utc_timestamp(raw.get("timestamp"))
    records = scenario_outcomes(raw.get("results"))
    claimed = boolean(raw.get("passed"))
    if claimed != all(records.values()):
        raise InvalidEvidence("inconsistent_lab_verdict")
    revisions = producer_revisions(raw.get("producer_revisions", {}))
    return {
        "schema_version": 1,
        "producer_revisions": revisions,
        "origin": "executed_lab_report",
        "execution": "saved",
        "captured_at": captured,
        "imported_at": now(),
        "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        "artifact_digest_kind": "raw_file_bytes",
        "record_sha256": hashlib.sha256(normalized).hexdigest(),
        "record_digest_format": RECORD_FORMAT,
        "backend": BACKEND,
        "passed": claimed,
        "scenarios": [
            {"id": number, "title": SCENARIOS[number], "passed": records[number]}
            for number in sorted(records)
        ],
        "limits": "Passed scenarios support their named lab checks, not full HIPAA compliance. "
        "This imported artifact does not prove the current cluster state.",
    }
