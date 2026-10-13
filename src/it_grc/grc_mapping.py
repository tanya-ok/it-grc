"""Versioned mapping from executed lab scenarios to NIST SP 800-66 rev2 requirement nodes.

Everything here is offline: the mapping file is validated, the lab report goes through the
strict `import_lab` validator, and the plan holds one deterministic JSON extract per evidence
group. The result ceiling is enforced on the mapping and again on every write in grc_push.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .lab_report import SCENARIOS, InvalidEvidence, canonical_record, import_lab, read_json_artifact

SCHEMA = "it-grc/mapping/v1"
FRAMEWORK_URN = "urn:intuitem:risk:framework:nist-sp-800-66-rev2"
NODE_URN = re.compile(r"urn:intuitem:risk:req_node:nist-sp-800-66-rev2:node[0-9]{1,4}")
VERSION = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}\.[0-9]{1,3}")
EVIDENCE_REF = re.compile(r"ITGRC-EV-[A-Z0-9-]{2,40}")
CONTROL_REF = re.compile(r"ITGRC-AC-[A-Z0-9-]{2,40}")
GAP_ID = re.compile(r"[a-z0-9][a-z0-9-]{1,60}")
AUDIT_REF = "ITGRC-800-66R2"
DOMAIN = "IT GRC Lab"
PERIMETER_REF = "ITGRC-LAB"
# The highest result and status the bridge may ever set. compliant, not_applicable and done
# are human decisions in CISO Assistant (ADR 0001).
CEILING = {"result": "partially_compliant", "status": "in_review"}
BRIDGE_RESULTS = frozenset({"not_assessed", "non_compliant", "partially_compliant"})
BRIDGE_STATUSES = frozenset({"to_do", "in_review"})
EXTENDED_RESULTS = frozenset({"observation_sensitive_point"})
CATEGORIES = frozenset({"policy", "process", "technical", "physical", "procedure"})
CSF_FUNCTIONS = frozenset({"govern", "identify", "protect", "detect", "respond", "recover"})
NOT_VERIFIED = "not_verified: "
MAX_TEXT = 600
DASHES = (chr(0x2014), chr(0x2013))
EXTRACT_LIMITS = (
    "Executed lab scenarios on synthetic data. Supports the named lab checks only; not a HIPAA "
    "compliance determination and not proof of the current cluster state."
)


class MappingError(ValueError):
    """Fixed messages; mapping text is never echoed back."""


class CeilingError(MappingError):
    """A value above the bridge ceiling was requested."""


def check_ceiling(result: object, status: object) -> None:
    """Refuse anything the bridge may not set. Used on the mapping and before every write."""
    if result not in BRIDGE_RESULTS:
        raise CeilingError(f"result {result!s:.40} is above the bridge ceiling or unknown")
    if status not in BRIDGE_STATUSES:
        raise CeilingError(f"status {status!s:.40} is above the bridge ceiling or unknown")


@dataclass(frozen=True)
class EvidenceGroup:
    ref_id: str
    name: str
    description: str
    scenarios: tuple[int, ...]


@dataclass(frozen=True)
class AppliedControl:
    ref_id: str
    name: str
    description: str
    category: str
    csf_function: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class Target:
    """One requirement node and what the bridge sets on its requirement assessment."""

    urn: str
    name: str
    section: str
    cfr: str
    result: str
    status: str
    extended_result: str | None
    evidence: tuple[str, ...]
    supporting: tuple[str, ...]
    controls: tuple[str, ...]
    rationale: str
    limits: str
    gap: str | None = None


@dataclass(frozen=True)
class Audit:
    ref_id: str
    name: str
    description: str
    domain: str
    perimeter: str


@dataclass(frozen=True)
class MappingFile:
    version: str
    sha256: str
    audit: Audit
    groups: tuple[EvidenceGroup, ...]
    controls: tuple[AppliedControl, ...]
    targets: tuple[Target, ...]

    def group(self, ref_id: str) -> EvidenceGroup:
        return next(group for group in self.groups if group.ref_id == ref_id)


def _object(value: Any, keys: set[str], what: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise MappingError(f"{what} must be an object with exactly the keys {sorted(keys)}")
    return value


def _text(value: Any, what: str, *, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise MappingError(f"{what} must be non-empty text of at most {limit} characters")
    if any(dash in value for dash in DASHES):
        raise MappingError(f"{what} must use plain hyphens")
    return value


def _refs(value: Any, known: set[str], what: str, *, empty: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or (not value and not empty):
        raise MappingError(f"{what} must be a list" + ("" if empty else " with entries"))
    if len(set(value)) != len(value) or not all(isinstance(item, str) for item in value):
        raise MappingError(f"{what} must hold unique ref ids")
    unknown = set(value) - known
    if unknown:
        raise MappingError(f"{what} names unknown ref ids: {', '.join(sorted(unknown))}")
    return tuple(value)


def _urn(value: Any, seen: set[str]) -> str:
    if not isinstance(value, str) or not NODE_URN.fullmatch(value):
        raise MappingError("every requirement URN must be a NIST SP 800-66 rev2 node URN")
    if value in seen:
        raise MappingError(f"requirement {value} is mapped twice")
    seen.add(value)
    return value


def _groups(rows: Any) -> tuple[EvidenceGroup, ...]:
    if not isinstance(rows, list) or not rows:
        raise MappingError("evidence_groups must be a non-empty list")
    groups: list[EvidenceGroup] = []
    covered: set[int] = set()
    for entry in rows:
        row = _object(entry, {"ref_id", "name", "scenarios", "description"}, "evidence group")
        ref_id = row["ref_id"]
        if not isinstance(ref_id, str) or not EVIDENCE_REF.fullmatch(ref_id):
            raise MappingError("evidence group ref_id must look like ITGRC-EV-NAME")
        name = _text(row["name"], f"{ref_id} name", limit=200)
        if not name.startswith(ref_id + " "):
            # CE evidence has no ref_id field; the exact name, led by the ref id, is the key.
            raise MappingError(f"{ref_id} name must start with its ref id")
        scenarios = row["scenarios"]
        if (
            not isinstance(scenarios, list)
            or not scenarios
            or any(type(n) is not int or n not in SCENARIOS for n in scenarios)
            or len(set(scenarios)) != len(scenarios)
        ):
            raise MappingError(f"{ref_id} scenarios must be unique lab scenario numbers")
        covered.update(scenarios)
        groups.append(
            EvidenceGroup(ref_id, name, _text(row["description"], ref_id), tuple(scenarios))
        )
    if len({group.ref_id for group in groups}) != len(groups):
        raise MappingError("evidence group ref ids must be unique")
    if len({group.name for group in groups}) != len(groups):
        raise MappingError("evidence group names must be unique")
    if covered != set(SCENARIOS):
        raise MappingError("evidence groups must cover every lab scenario")
    return tuple(groups)


def _controls(rows: Any, groups: set[str]) -> tuple[AppliedControl, ...]:
    if not isinstance(rows, list):
        raise MappingError("applied_controls must be a list")
    controls: list[AppliedControl] = []
    for entry in rows:
        row = _object(
            entry,
            {"ref_id", "name", "category", "csf_function", "evidence", "description"},
            "applied control",
        )
        ref_id = row["ref_id"]
        if not isinstance(ref_id, str) or not CONTROL_REF.fullmatch(ref_id):
            raise MappingError("applied control ref_id must look like ITGRC-AC-NAME")
        if row["category"] not in CATEGORIES or row["csf_function"] not in CSF_FUNCTIONS:
            raise MappingError(f"{ref_id} has an unknown category or CSF function")
        controls.append(
            AppliedControl(
                ref_id,
                _text(row["name"], f"{ref_id} name", limit=200),
                _text(row["description"], ref_id),
                row["category"],
                row["csf_function"],
                _refs(row["evidence"], groups, f"{ref_id} evidence", empty=True),
            )
        )
    if len({control.ref_id for control in controls}) != len(controls):
        raise MappingError("applied control ref ids must be unique")
    return tuple(controls)


def _requirements(rows: Any, groups: set[str], controls: set[str], seen: set[str]) -> list[Target]:
    if not isinstance(rows, list) or not rows:
        raise MappingError("requirements must be a non-empty list")
    keys = {
        "urn",
        "name",
        "section",
        "cfr",
        "result",
        "status",
        "extended_result",
        "evidence",
        "supporting_evidence",
        "applied_controls",
        "rationale",
        "limits",
    }
    targets = []
    for entry in rows:
        row = _object(entry, keys, "requirement")
        urn = _urn(row["urn"], seen)
        check_ceiling(row["result"], row["status"])
        if (row["result"], row["status"]) != (CEILING["result"], CEILING["status"]):
            raise MappingError(f"{urn}: an evidenced requirement goes to partially_compliant")
        extended = row["extended_result"]
        if extended is not None and extended not in EXTENDED_RESULTS:
            raise MappingError(f"{urn}: unsupported extended result")
        evidence = _refs(row["evidence"], groups, f"{urn} evidence", empty=False)
        supporting = _refs(row["supporting_evidence"], groups, f"{urn} supporting", empty=True)
        if set(evidence) & set(supporting):
            raise MappingError(f"{urn}: a group is both basis and supporting evidence")
        targets.append(
            Target(
                urn=urn,
                name=_text(row["name"], f"{urn} name", limit=300),
                section=_text(row["section"], f"{urn} section", limit=40),
                cfr=_text(row["cfr"], f"{urn} cfr", limit=80),
                result=row["result"],
                status=row["status"],
                extended_result=extended,
                evidence=evidence,
                supporting=supporting,
                controls=_refs(row["applied_controls"], controls, f"{urn} controls", empty=True),
                rationale=_text(row["rationale"], f"{urn} rationale"),
                limits=_text(row["limits"], f"{urn} limits"),
            )
        )
    return targets


def _gaps(rows: Any, seen: set[str]) -> list[Target]:
    if not isinstance(rows, list):
        raise MappingError("not_verified must be a list")
    targets = []
    for entry in rows:
        row = _object(entry, {"id", "cfr", "result", "status", "reason", "nodes"}, "not_verified")
        gap = row["id"]
        if not isinstance(gap, str) or not GAP_ID.fullmatch(gap):
            raise MappingError("not_verified ids must be lowercase words joined by hyphens")
        check_ceiling(row["result"], row["status"])
        if (row["result"], row["status"]) != ("not_assessed", "to_do"):
            raise MappingError(f"{gap}: a gap without evidence stays not_assessed and to_do")
        reason = _text(row["reason"], f"{gap} reason")
        nodes = row["nodes"]
        if not isinstance(nodes, list) or not nodes:
            raise MappingError(f"{gap} needs at least one node")
        for node in nodes:
            item = _object(node, {"urn", "name", "section"}, f"{gap} node")
            urn = _urn(item["urn"], seen)
            targets.append(
                Target(
                    urn=urn,
                    name=_text(item["name"], f"{urn} name", limit=300),
                    section=_text(item["section"], f"{urn} section", limit=40),
                    cfr=_text(row["cfr"], f"{gap} cfr", limit=80),
                    result="not_assessed",
                    status="to_do",
                    extended_result=None,
                    evidence=(),
                    supporting=(),
                    controls=(),
                    rationale=reason,
                    limits="",
                    gap=gap,
                )
            )
    return targets


def parse_mapping(raw: Mapping[str, Any], digest: str) -> MappingFile:
    """Validate a decoded mapping document. Refuses anything above the ceiling."""
    keys = {
        "schema",
        "version",
        "framework",
        "verified",
        "claims",
        "ceiling",
        "audit",
        "evidence_groups",
        "applied_controls",
        "requirements",
        "not_verified",
    }
    raw = _object(dict(raw), keys, "mapping")
    if raw["schema"] != SCHEMA:
        raise MappingError(f"mapping schema must be {SCHEMA}")
    version = raw["version"]
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise MappingError("mapping version must look like YYYY-MM-DD.N")
    if raw["framework"] != FRAMEWORK_URN:
        raise MappingError("the mapping must target the NIST SP 800-66 rev2 framework")
    if raw["ceiling"] != CEILING:
        raise CeilingError("the mapping ceiling must be partially_compliant and in_review")
    _object(raw["verified"], {"on", "against", "method"}, "verified")
    _text(raw["claims"], "claims")
    audit = _object(raw["audit"], {"ref_id", "name", "description", "domain", "perimeter"}, "audit")
    if (audit["ref_id"], audit["domain"], audit["perimeter"]) != (
        AUDIT_REF,
        DOMAIN,
        PERIMETER_REF,
    ):
        raise MappingError("the mapping must target the lab audit, domain and perimeter")
    groups = _groups(raw["evidence_groups"])
    group_ids = {group.ref_id for group in groups}
    controls = _controls(raw["applied_controls"], group_ids)
    seen: set[str] = set()
    targets = _requirements(
        raw["requirements"], group_ids, {control.ref_id for control in controls}, seen
    )
    targets += _gaps(raw["not_verified"], seen)
    linked = {ref for target in targets for ref in (*target.evidence, *target.supporting)}
    if group_ids - linked:
        raise MappingError("every evidence group must be linked to a requirement")
    return MappingFile(
        version=version,
        sha256=digest,
        audit=Audit(
            AUDIT_REF,
            _text(audit["name"], "audit name", limit=200),
            _text(audit["description"], "audit description"),
            DOMAIN,
            PERIMETER_REF,
        ),
        groups=groups,
        controls=controls,
        targets=tuple(targets),
    )


def load_mapping(path: Path) -> MappingFile:
    try:
        raw, data = read_json_artifact(path)
    except InvalidEvidence as error:
        raise MappingError(f"the mapping file is not valid JSON ({error})") from None
    except OSError:
        raise MappingError("the mapping file cannot be read") from None
    return parse_mapping(raw, hashlib.sha256(data).hexdigest())


# Lab report and plan


def load_report(path: Path) -> dict[str, Any]:
    """The strict lab-report validator's summary, without its import time."""
    try:
        raw, artifact = read_json_artifact(path)
        summary = import_lab(raw, artifact)
    except InvalidEvidence as error:
        raise MappingError(f"the lab report was refused ({error})") from None
    except OSError:
        raise MappingError("the lab report cannot be read") from None
    del summary["imported_at"]
    return summary


@dataclass(frozen=True)
class Extract:
    group: EvidenceGroup
    file_name: str
    content: bytes
    sha256: str
    passed: bool


@dataclass(frozen=True)
class Planned:
    """What the bridge sets on one requirement assessment."""

    target: Target
    result: str
    status: str
    observation: str
    failed: tuple[int, ...]


@dataclass(frozen=True)
class Plan:
    mapping: MappingFile
    report: dict[str, Any]
    extracts: tuple[Extract, ...]
    requirements: tuple[Planned, ...]

    def extract(self, ref_id: str) -> Extract:
        return next(item for item in self.extracts if item.group.ref_id == ref_id)


def extract(group: EvidenceGroup, report: Mapping[str, Any]) -> Extract:
    """Deterministic JSON for one evidence group: validated fields only, no free text from
    the report, so the same report always yields the same bytes and hash."""
    outcomes = {row["id"]: row for row in report["scenarios"]}
    rows = [outcomes[number] for number in group.scenarios]
    document = {
        "kind": "it-grc-lab-evidence-extract",
        "format": 1,
        "evidence": group.ref_id,
        "source": {
            "origin": report["origin"],
            "backend": report["backend"],
            "captured_at": report["captured_at"],
            "artifact_sha256": report["artifact_sha256"],
            "artifact_digest_kind": report["artifact_digest_kind"],
            "record_sha256": report["record_sha256"],
            "record_digest_format": report["record_digest_format"],
            "producer_revisions": report["producer_revisions"],
        },
        "scenarios": [
            {"id": row["id"], "title": row["title"], "passed": row["passed"]} for row in rows
        ],
        "limits": EXTRACT_LIMITS,
    }
    content = canonical_record(document) + b"\n"
    return Extract(
        group=group,
        file_name=f"{group.ref_id.lower()}.json",
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        passed=all(row["passed"] for row in rows),
    )


def scenario_list(numbers: list[int]) -> str:
    return ", ".join(f"S{number}" for number in sorted(numbers))


def plan_target(mapping: MappingFile, target: Target, report: Mapping[str, Any]) -> Planned:
    tag = f"(it-grc mapping {mapping.version}, {target.cfr})"
    if target.gap is not None:
        observation = f"{NOT_VERIFIED}{target.rationale} {tag}"
        return Planned(target, target.result, target.status, observation, ())
    outcomes = {row["id"]: row["passed"] for row in report["scenarios"]}
    basis = {n for ref in target.evidence for n in mapping.group(ref).scenarios}
    supporting = {n for ref in target.supporting for n in mapping.group(ref).scenarios}
    failed = sorted(n for n in basis | supporting if not outcomes[n])
    result = target.result
    lines = [f"Lab evidence {tag}: {target.rationale}", f"Limits: {target.limits}"]
    if any(n in basis for n in failed):
        # A failed basis scenario is a proven lab failure, not missing evidence.
        result = "non_compliant"
    if failed:
        lines.append(f"Failed in the report: {scenario_list(failed)}.")
    lines.append(
        "Set by the it-grc bridge at most partially_compliant and in_review; compliant and done"
        " are human decisions. Lab evidence is not HIPAA compliance."
    )
    check_ceiling(result, target.status)
    return Planned(target, result, target.status, "\n".join(lines), tuple(failed))


def build_plan(mapping: MappingFile, report: dict[str, Any]) -> Plan:
    extracts = tuple(extract(group, report) for group in mapping.groups)
    requirements = tuple(plan_target(mapping, target, report) for target in mapping.targets)
    return Plan(mapping, report, extracts, requirements)


def report_digest(report: Mapping[str, Any]) -> str:
    return str(report["record_sha256"])
