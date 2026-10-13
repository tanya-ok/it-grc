"""Push executed lab evidence into CISO Assistant, and verify it later.

`push` validates the lab report, builds the plan from the versioned mapping and then, with
the bridge token (Analyst role), ensures the audit, one evidence object per scenario group,
evidence revisions, applied controls and the mapped requirement assessments. Every object is
found by a stable key before anything is created, so a second run changes nothing.

Safety rules (ADR 0001):

- Every write passes `guard`, an allowlist of routes and fields. It refuses any result above
  partially_compliant, any status above in_review, evidence approval, locking and deletion.
- Requirement lookups assert exactly one assessable match with the exact URN, and the node
  name and section must still equal the mapping, so a changed library stops the push.
- A requirement a human has taken over (status in_progress or done, result compliant or
  not_applicable, accepted review, locked) is left alone and reported.
- Output passes the redactor and never contains the token.
- Every push that sends a write appends one record to the local hash-chained ledger
  (grc_ledger). `verify` reconciles CISO Assistant against the latest complete record.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import grc_ledger
from .grc_client import GrcClient, GrcError, GrcLookupError, ref, route
from .grc_mapping import (
    AUDIT_REF,
    DOMAIN,
    FRAMEWORK_URN,
    PERIMETER_REF,
    CeilingError,
    Extract,
    MappingError,
    Plan,
    Planned,
    build_plan,
    check_ceiling,
    load_mapping,
    load_report,
)
from .grc_ops import (
    BRIDGE_EMAIL,
    BRIDGE_PAT_FILE,
    OBJECT_ID,
    OpsError,
    Redactor,
    Say,
    Settings,
    check_bridge_identity,
    connect,
    object_id,
    root_folder,
)
from .lab_report import SCENARIOS

AUDIT_STATUS = "in_progress"
# Routes and fields the bridge may write. Nothing else is ever sent.
ALLOWED_WRITES: dict[tuple[str, str], frozenset[str]] = {
    ("POST", "/compliance-assessments/"): frozenset(
        {"name", "ref_id", "description", "perimeter", "framework", "folder", "status"}
    ),
    ("POST", "/evidences/"): frozenset({"name", "description", "folder"}),
    ("POST", "/evidence-revisions/"): frozenset({"evidence", "folder", "observation"}),
    ("POST", "/applied-controls/"): frozenset(
        {"name", "ref_id", "description", "folder", "category", "csf_function", "evidences"}
    ),
    ("PATCH", "/applied-controls/{id}/"): frozenset({"evidences"}),
    ("PATCH", "/requirement-assessments/{id}/"): frozenset(
        {"result", "status", "observation", "extended_result", "evidences", "applied_controls"}
    ),
}
HUMAN_RESULTS = frozenset({"compliant", "not_applicable"})
CE_VERSION = re.compile(r"v?[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:[-+.][0-9A-Za-z.-]{1,40})?")


class DriftError(OpsError):
    """verify found differences between CISO Assistant and the local plan."""


def guard(method: str, path: str, body: Mapping[str, Any]) -> None:
    """Refuse any write outside the allowlist or above the result ceiling."""
    allowed = ALLOWED_WRITES.get((method, route(path)))
    if allowed is None:
        raise CeilingError(f"refusing {method} {route(path)}: not a bridge write")
    extra = set(body) - allowed
    if extra:
        raise CeilingError(f"refusing {method} {route(path)}: fields {sorted(extra)} not allowed")
    if route(path) == "/compliance-assessments/" and body.get("status") != AUDIT_STATUS:
        raise CeilingError("refusing an audit status other than in_progress")
    if route(path) == "/requirement-assessments/{id}/":
        if "result" in body:
            check_ceiling(body["result"], "to_do")
        if "status" in body:
            check_ceiling("not_assessed", body["status"])


@dataclass
class Writer:
    """All push writes. In a dry run, writes are listed and never sent."""

    client: GrcClient
    dry_run: bool
    say: Say
    changes: list[str] = field(default_factory=list)

    def note(self, change: str) -> None:
        self.changes.append(change)
        self.say(("Would " if self.dry_run else "Changed: ") + change)

    def post(self, path: str, body: Mapping[str, Any], change: str) -> None:
        guard("POST", path, body)
        self.note(change)
        if not self.dry_run:
            self.client.post(path, dict(body))

    def patch(self, path: str, body: Mapping[str, Any], change: str) -> None:
        guard("PATCH", path, body)
        self.note(change)
        if not self.dry_run:
            self.client.patch(path, dict(body))

    def upload(self, fields: Mapping[str, str], item: Extract, change: str) -> None:
        guard("POST", "/evidence-revisions/", fields)
        self.note(change)
        if not self.dry_run:
            self.client.post_form(
                "/evidence-revisions/",
                fields,
                file_field="attachment",
                file_name=item.file_name,
                content=item.content,
            )


@dataclass(frozen=True)
class Links:
    """Server ids of the evidence objects and applied controls, keyed by ref id. None in a
    dry run for objects that do not exist yet, or in verify for missing objects."""

    evidence: Mapping[str, str | None]
    controls: Mapping[str, str | None]


@dataclass(frozen=True)
class Context:
    bridge: GrcClient
    domain: str
    perimeter: str
    framework: str


def resolve(bridge: GrcClient) -> Context:
    """The lab domain, perimeter and framework, each asserted as exactly one match."""
    root = root_folder(bridge)
    wanted = {"name": DOMAIN, "parent_folder": root}
    domain = bridge.one("/folders/", wanted, honors=wanted, match={}, what="domain")
    if domain.get("content_type") not in {"DO", "DOMAIN"}:
        raise OpsError(f"{DOMAIN!r} is not a domain; refusing to use it")
    domain_id = object_id(domain)
    perimeter = bridge.one(
        "/perimeters/",
        {"folder": domain_id},
        honors={"folder": domain_id},
        match={"ref_id": PERIMETER_REF},
        what="perimeter",
    )
    framework = bridge.framework(FRAMEWORK_URN)
    return Context(bridge, domain_id, object_id(perimeter), object_id(framework))


def in_domain(row: Mapping[str, Any], ctx: Context, what: str) -> str:
    if ref(row.get("folder")) != ctx.domain:
        raise OpsError(f"{what} exists outside the {DOMAIN!r} domain; refusing to use it")
    return object_id(dict(row))


def by_key(rows: list[dict[str, Any]], key: str, value: str, what: str) -> dict[str, Any] | None:
    hits = [row for row in rows if row.get(key) == value]
    if len(hits) > 1:
        raise GrcLookupError(f"{what}: expected at most one match, found {len(hits)}")
    return hits[0] if hits else None


def check_nodes(ctx: Context, plan: Plan) -> None:
    """Every mapped URN resolves to exactly one assessable node with the recorded name."""
    for planned in plan.requirements:
        target = planned.target
        node = ctx.bridge.requirement_node(target.urn)
        section = str(node.get("parent_urn") or "").rsplit(":", 1)[-1]
        if ref(node.get("framework")) != ctx.framework:
            raise OpsError(f"{target.urn} belongs to another framework")
        if node.get("name") != target.name or section != target.section:
            raise OpsError(f"{target.urn} no longer matches the mapping; review the library")


def find_audit(ctx: Context) -> dict[str, Any] | None:
    # Every visible audit is listed and the ref id is matched here, so an audit with this ref
    # id anywhere the bridge can see is found, whatever filters the API honors.
    audit = ctx.bridge.find(
        "/compliance-assessments/", {}, honors={}, match={"ref_id": AUDIT_REF}, what="audit"
    )
    if audit is None:
        return None
    if (
        ref(audit.get("folder")) != ctx.domain
        or ref(audit.get("perimeter")) != ctx.perimeter
        or ref(audit.get("framework")) != ctx.framework
    ):
        raise OpsError(
            f"Audit {AUDIT_REF} exists outside the lab perimeter or for another framework;"
            " refusing to use it"
        )
    return audit


def ensure_audit(writer: Writer, ctx: Context, plan: Plan) -> str | None:
    audit = find_audit(ctx)
    if audit is None:
        info = plan.mapping.audit
        writer.post(
            "/compliance-assessments/",
            {
                "name": info.name,
                "ref_id": info.ref_id,
                "description": info.description,
                "perimeter": ctx.perimeter,
                "framework": ctx.framework,
                "folder": ctx.domain,
                "status": AUDIT_STATUS,
            },
            f"create audit {AUDIT_REF} in {DOMAIN!r} / {PERIMETER_REF}",
        )
        if writer.dry_run:
            return None
        audit = find_audit(ctx)
        if audit is None:
            raise GrcLookupError("audit: expected one match, found 0")
    if audit.get("is_locked") is True:
        raise OpsError(f"Audit {AUDIT_REF} is locked; the bridge never unlocks an audit")
    if audit.get("status") in {"done", "deprecated"}:
        raise OpsError(f"Audit {AUDIT_REF} is {audit.get('status')}; the bridge leaves it alone")
    return object_id(audit)


def revisions(ctx: Context, evidence: str) -> list[dict[str, Any]]:
    rows = ctx.bridge.select(
        "/evidence-revisions/",
        {"evidence": evidence},
        honors={"evidence": evidence},
        what="evidence revisions",
    )
    if any(type(row.get("version")) is not int for row in rows):
        raise OpsError("An evidence revision has no version number")
    return sorted(rows, key=lambda row: int(row["version"]))


def latest_hash(ctx: Context, evidence: str) -> tuple[int, str | None]:
    rows = revisions(ctx, evidence)
    if not rows:
        return 0, None
    value = rows[-1].get("attachment_hash")
    return int(rows[-1]["version"]), value if isinstance(value, str) else None


def ensure_evidence(writer: Writer, ctx: Context, plan: Plan) -> dict[str, str | None]:
    """One evidence object per scenario group, found by its exact name (CE evidence has no
    ref_id), and a new revision only when the extract hash differs from the latest one."""
    ids: dict[str, str | None] = {}
    rows = ctx.bridge.list_all("/evidences/")
    report = plan.report
    for item in plan.extracts:
        group = item.group
        row = by_key(rows, "name", group.name, f"evidence {group.ref_id}")
        if row is None:
            writer.post(
                "/evidences/",
                {"name": group.name, "description": group.description, "folder": ctx.domain},
                f"create evidence {group.ref_id}",
            )
            if not writer.dry_run:
                row = by_key(ctx.bridge.list_all("/evidences/"), "name", group.name, group.ref_id)
                if row is None:
                    raise GrcLookupError(f"evidence {group.ref_id}: expected one match, found 0")
        evidence = in_domain(row, ctx, f"Evidence {group.ref_id}") if row else None
        ids[group.ref_id] = evidence
        version, stored = latest_hash(ctx, evidence) if evidence else (0, None)
        if stored == item.sha256:
            continue
        observation = (
            f"it-grc push, mapping {plan.mapping.version}: lab report captured"
            f" {report['captured_at']}, record sha256 {report['record_sha256']}"
        )
        writer.upload(
            {"evidence": evidence or "", "folder": ctx.domain, "observation": observation},
            item,
            f"upload {group.ref_id} revision {version + 1} (sha256 {item.sha256})",
        )
        if evidence and not writer.dry_run:
            check_upload(ctx, evidence, version, item)
    return ids


def check_upload(ctx: Context, evidence: str, before: int, item: Extract) -> None:
    version, stored = latest_hash(ctx, evidence)
    if version <= before:
        raise OpsError(f"No new revision appeared for {item.group.ref_id}")
    if stored != item.sha256:
        raise OpsError(
            f"Stored attachment hash of {item.group.ref_id} revision {version} differs from"
            f" the local sha256 {item.sha256}"
        )


def control_evidence(ctx: Context, identifier: str) -> set[str]:
    """Evidence ids linked to an applied control. List rows omit them; the detail has them."""
    detail = ctx.bridge.get(f"/applied-controls/{identifier}/")
    if not isinstance(detail, dict) or ref(detail.get("id")) != identifier:
        raise OpsError("An applied control answered with an unexpected shape")
    return ids_of(detail.get("evidences"))


def ensure_controls(
    writer: Writer, ctx: Context, plan: Plan, evidence: Mapping[str, str | None]
) -> dict[str, str | None]:
    ids: dict[str, str | None] = {}
    rows = ctx.bridge.list_all("/applied-controls/")
    for control in plan.mapping.controls:
        linked = sorted(str(evidence[ref_id]) for ref_id in control.evidence if evidence[ref_id])
        row = by_key(rows, "ref_id", control.ref_id, f"applied control {control.ref_id}")
        if row is None:
            writer.post(
                "/applied-controls/",
                {
                    "name": control.name,
                    "ref_id": control.ref_id,
                    "description": control.description,
                    "folder": ctx.domain,
                    "category": control.category,
                    "csf_function": control.csf_function,
                    "evidences": linked,
                },
                f"create applied control {control.ref_id}",
            )
            if writer.dry_run:
                ids[control.ref_id] = None
                continue
            row = by_key(
                ctx.bridge.list_all("/applied-controls/"), "ref_id", control.ref_id, control.ref_id
            )
            if row is None:
                raise GrcLookupError(f"applied control {control.ref_id}: expected one, found 0")
        identifier = in_domain(row, ctx, f"Applied control {control.ref_id}")
        if row.get("name") != control.name:
            raise OpsError(f"Applied control {control.ref_id} was renamed; refusing to use it")
        current = control_evidence(ctx, identifier)
        if set(linked) - current:
            writer.patch(
                f"/applied-controls/{identifier}/",
                {"evidences": sorted(current | set(linked))},
                f"link evidence to applied control {control.ref_id}",
            )
        ids[control.ref_id] = identifier
    return ids


def held(row: Mapping[str, Any]) -> str | None:
    """Why a requirement assessment belongs to a human now, or None."""
    if row.get("is_locked") is True:
        return "locked"
    if row.get("result") in HUMAN_RESULTS:
        return f"result {row.get('result')}"
    if row.get("status") not in {"to_do", "in_review"}:
        return f"status {row.get('status')}"
    if row.get("review_state") == "accepted":
        return "review accepted"
    return None


def ids_of(values: Any) -> set[str]:
    return {str(ref(value)) for value in values or []}


def state(row: Mapping[str, Any]) -> dict[str, str]:
    """Result and status of a requirement assessment as the ledger records them."""
    return {"result": f"{row.get('result')!s:.40}", "status": f"{row.get('status')!s:.40}"}


@dataclass(frozen=True)
class Observed:
    """A mapped requirement after the push: what was planned and what the server shows."""

    planned: Planned
    observed: dict[str, str] | None
    held: str | None


def desired(row: Mapping[str, Any], planned: Planned, links: Links) -> dict[str, Any]:
    """The fields that differ from the plan; empty when the row matches."""
    target = planned.target
    evidence, controls = links.evidence, links.controls
    body: dict[str, Any] = {}
    if row.get("result") != planned.result:
        body["result"] = planned.result
    if row.get("status") != planned.status:
        body["status"] = planned.status
    if (row.get("observation") or "") != planned.observation:
        body["observation"] = planned.observation
    if target.extended_result and row.get("extended_result") != target.extended_result:
        body["extended_result"] = target.extended_result
    wanted = {evidence[r] for r in (*target.evidence, *target.supporting) if evidence[r]}
    current = ids_of(row.get("evidences"))
    if {str(value) for value in wanted} - current:
        body["evidences"] = sorted(current | {str(value) for value in wanted})
    wanted_controls = {str(controls[r]) for r in target.controls if controls[r]}
    current_controls = ids_of(row.get("applied_controls"))
    if wanted_controls - current_controls:
        body["applied_controls"] = sorted(current_controls | wanted_controls)
    return body


def update_requirements(
    writer: Writer, ctx: Context, plan: Plan, audit: str | None, links: Links
) -> list[Observed]:
    seen: list[Observed] = []
    for planned in plan.requirements:
        target = planned.target
        if audit is None:
            count = len(target.evidence) + len(target.supporting) + len(target.controls)
            detail = f"{count} link(s)" if target.gap is None else "a not_verified observation"
            writer.note(
                f"set {target.urn} ({target.cfr}) to {planned.result} / {planned.status}"
                f" with {detail}"
            )
            seen.append(Observed(planned, None, None))
            continue
        row = ctx.bridge.requirement_assessment(audit, target.urn)
        reason = held(row)
        if reason is not None:
            writer.say(f"HELD {target.urn}: {reason}; a human decision is kept unchanged")
            seen.append(Observed(planned, state(row), reason))
            continue
        body = desired(row, planned, links)
        if body:
            identifier = object_id(row)
            writer.patch(
                f"/requirement-assessments/{identifier}/",
                body,
                f"set {', '.join(sorted(body))} on {target.urn} ({target.cfr})",
            )
            if not writer.dry_run:
                row = ctx.bridge.requirement_assessment(audit, target.urn)
                if desired(row, planned, links):
                    raise OpsError(f"{target.urn} did not read back as written")
        seen.append(Observed(planned, state(row), None))
    return seen


# Ledger records


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def ce_version(bridge: GrcClient) -> str:
    """The CISO Assistant build version, recorded with every push."""
    answer = bridge.get("/build/")
    version = answer.get("version") if isinstance(answer, dict) else None
    if not isinstance(version, str) or not CE_VERSION.fullmatch(version):
        raise OpsError("GET /build/ answered without a recognizable version")
    return version


def revision_rows(ctx: Context, evidence: str) -> list[dict[str, Any]]:
    """Every revision of an evidence object: id, version and stored attachment hash."""
    rows = []
    for row in revisions(ctx, evidence):
        value = row.get("attachment_hash")
        stored = value if isinstance(value, str) and grc_ledger.HEX64.fullmatch(value) else None
        rows.append(
            {"id": object_id(row), "version": int(row["version"]), "attachment_hash": stored}
        )
    return rows


def base_record(plan: Plan, version: str | None, outcome: str, writes: list[str]) -> dict[str, Any]:
    return {
        "time": utc_now(),
        "outcome": outcome,
        "ce_version": version,
        "actor": BRIDGE_EMAIL,
        "mapping": {"version": plan.mapping.version, "sha256": plan.mapping.sha256},
        "report": plan.report,
        "writes": list(writes),
    }


def push_record(  # noqa: PLR0913, PLR0917 - one record from the results of each push step
    ctx: Context,
    plan: Plan,
    version: str,
    audit: str,
    links: Links,
    seen: list[Observed],
    writes: list[str],
) -> dict[str, Any]:
    """The ledger body of a complete push, read back from CISO Assistant."""
    record = base_record(plan, version, "complete", writes)
    record["audit"] = {"id": audit, "ref_id": AUDIT_REF}
    record["evidence"] = [
        {
            "ref_id": item.group.ref_id,
            "id": str(links.evidence[item.group.ref_id]),
            "extract_sha256": item.sha256,
            "revisions": revision_rows(ctx, str(links.evidence[item.group.ref_id])),
        }
        for item in plan.extracts
    ]
    record["controls"] = [
        {
            "ref_id": control.ref_id,
            "id": str(links.controls[control.ref_id]),
            "evidence": sorted(control_evidence(ctx, str(links.controls[control.ref_id]))),
        }
        for control in plan.mapping.controls
    ]
    record["requirements"] = [
        {
            "urn": item.planned.target.urn,
            "planned": {"result": item.planned.result, "status": item.planned.status},
            "observed": item.observed,
            "held": item.held,
        }
        for item in seen
    ]
    return record


def record_failure(  # noqa: PLR0913, PLR0917 - the failed push and its context
    settings: Settings,
    redactor: Redactor,
    say: Say,
    plan: Plan,
    version: str | None,
    writes: list[str],
    error: BaseException,
) -> None:
    """A push that sent writes and then failed is recorded too, with the writes it sent."""
    record = base_record(plan, version, "failed", writes)
    known = isinstance(error, GrcError | OpsError | MappingError)
    record["error"] = redactor(f"{error!s:.300}") if known else type(error).__name__
    try:
        appended = grc_ledger.append(grc_ledger.data_folder(settings, redactor), record, redactor)
    except (OSError, OpsError):
        say("WARNING the failed push could not be recorded in the ledger")
        return
    say(f"Ledger: record {appended['seq']} records the failed push ({len(writes)} write(s) sent)")


def valid_summary(report: Any) -> bool:
    """The recorded report summary has the shape `load_report` produces."""
    hexes = ("artifact_sha256", "record_sha256")
    if not isinstance(report, dict) or not all(
        isinstance(report.get(key), str) and len(report[key]) == 64 for key in hexes
    ):
        return False
    rows = report.get("scenarios")
    return (
        isinstance(rows, list)
        and [row.get("id") if isinstance(row, dict) else None for row in rows] == list(SCENARIOS)
        and all(row.get("title") == SCENARIOS[row["id"]] for row in rows)
        and all(type(row.get("passed")) is bool for row in rows)
        and all(isinstance(report.get(key), str) for key in ("captured_at", "backend", "origin"))
        and isinstance(report.get("producer_revisions"), dict)
    )


# Commands


def prepare(settings: Settings, redactor: Redactor) -> tuple[GrcClient, Context]:
    vault, client = connect(settings, redactor)
    bridge = client.with_token(vault.read(BRIDGE_PAT_FILE))
    check_bridge_identity(bridge)
    return bridge, resolve(bridge)


def mapping_path(settings: Settings) -> Path:
    if settings.mapping is None:
        raise OpsError("No mapping file configured")
    return settings.mapping


def push(settings: Settings, say: Say, redactor: Redactor) -> list[str]:
    if settings.report is None:
        raise OpsError("push needs --report <path>")
    mapping = load_mapping(mapping_path(settings))
    plan = build_plan(mapping, load_report(settings.report))
    report = plan.report
    say(
        f"Report captured {report['captured_at']}: {len(report['scenarios'])} scenarios,"
        f" passed={report['passed']}, record sha256 {report['record_sha256']}"
    )
    say(f"Mapping {mapping.version} (sha256 {mapping.sha256}): {len(plan.requirements)} targets")
    folder = grc_ledger.data_folder(settings, redactor)
    ledger = grc_ledger.verify_ledger(folder)
    for warning in ledger.warnings:
        say(f"WARNING ledger: {warning}")
    say(f"PASS ledger: {len(ledger.records)} record(s) verified before the push")
    bridge, ctx = prepare(settings, redactor)
    version = ce_version(bridge)
    say(f"CISO Assistant {version}")
    writer = Writer(bridge, settings.dry_run, say)
    try:
        check_nodes(ctx, plan)
        say(f"PASS {len(plan.requirements)} requirement URNs: exactly one assessable node each")
        audit = ensure_audit(writer, ctx, plan)
        evidence = ensure_evidence(writer, ctx, plan)
        controls = ensure_controls(writer, ctx, plan, evidence)
        links = Links(evidence, controls)
        seen = update_requirements(writer, ctx, plan, audit, links)
        if settings.dry_run:
            say(f"Dry run: {len(writer.changes)} planned change(s); nothing was written")
            return writer.changes
        record = push_record(ctx, plan, version, str(audit), links, seen, writer.changes)
    except BaseException as error:
        if not settings.dry_run and writer.changes:
            record_failure(settings, redactor, say, plan, version, writer.changes, error)
        raise
    try:
        appended = grc_ledger.append(folder, record, redactor)
    except (OSError, OpsError) as error:
        shown = redactor(str(error)) if isinstance(error, OpsError) else "the file is unwritable"
        raise OpsError(f"The push finished but the ledger append failed: {shown}") from None
    say(f"Ledger: appended record {appended['seq']} (record_hash {appended['record_hash']})")
    kept = [item for item in seen if item.held is not None]
    if kept:
        say(f"WARNING {len(kept)} requirement(s) held by human decisions; run `it-grc verify`")
    count = len(writer.changes)
    say(f"Push complete: {count} change(s)" if count else "Push complete: no changes")
    return writer.changes


def coverage_summary(bridge: GrcClient, audit: str) -> str:
    answer = bridge.get(f"/compliance-assessments/{audit}/evidence_coverage/")
    if not isinstance(answer, dict):
        return "unavailable"
    parts = [
        f"{key}={value}" for key, value in sorted(answer.items()) if type(value) in {int, float}
    ]
    return ", ".join(parts) if parts else "no numeric fields"


def counts(values: Counter[str]) -> str:
    return ", ".join(f"{key}={value}" for key, value in sorted(values.items())) or "none"


def audit_summary(ctx: Context, audit: str, say: Say) -> None:
    """Result and status counts over the assessable requirements, and evidence coverage."""
    rows = ctx.bridge.select(
        "/requirement-assessments/",
        {"compliance_assessment": audit},
        honors={"compliance_assessment": audit},
        what="requirement assessments",
    )
    assessable = [row for row in rows if row.get("assessable") is True]
    results = Counter(str(row.get("result")) for row in assessable)
    statuses = Counter(str(row.get("status")) for row in assessable)
    say(f"Results ({len(assessable)} assessable): {counts(results)}")
    say(f"Statuses: {counts(statuses)}")
    say(f"Evidence coverage: {coverage_summary(ctx.bridge, audit)}")


# Verify against the latest complete ledger record


@dataclass(frozen=True)
class Recorded:
    """The latest complete ledger record, shape-checked before verify relies on it."""

    seq: int
    time: str
    ce_version: str
    mapping_sha256: str
    report: dict[str, Any]
    audit: str
    evidence: Mapping[str, tuple[str, list[dict[str, Any]]]]
    controls: Mapping[str, str]
    requirements: Mapping[str, tuple[dict[str, str] | None, str | None]]


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or not OBJECT_ID.fullmatch(value):
        raise ValueError
    return value


def _revision(row: Any) -> dict[str, Any]:
    stored = row["attachment_hash"]
    if type(row["version"]) is not int or not (
        stored is None or (isinstance(stored, str) and grc_ledger.HEX64.fullmatch(stored))
    ):
        raise ValueError
    return {"id": _identifier(row["id"]), "version": row["version"], "attachment_hash": stored}


def _observed(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"result", "status"}:
        raise ValueError
    if not all(isinstance(item, str) for item in value.values()):
        raise ValueError
    return {"result": value["result"], "status": value["status"]}


def recorded(record: Mapping[str, Any]) -> Recorded:
    try:
        audit, mapping = record["audit"], record["mapping"]
        if (
            not valid_summary(record["report"])
            or audit["ref_id"] != AUDIT_REF
            or not isinstance(mapping["sha256"], str)
            or not isinstance(record["ce_version"], str)
            or not isinstance(record["time"], str)
        ):
            raise ValueError
        evidence = {
            str(row["ref_id"]): (_identifier(row["id"]), [_revision(r) for r in row["revisions"]])
            for row in record["evidence"]
        }
        controls = {str(row["ref_id"]): _identifier(row["id"]) for row in record["controls"]}
        requirements: dict[str, tuple[dict[str, str] | None, str | None]] = {}
        for row in record["requirements"]:
            reason = row["held"]
            if reason is not None and not isinstance(reason, str):
                raise ValueError
            requirements[str(row["urn"])] = (_observed(row["observed"]), reason)
        return Recorded(
            seq=int(record["seq"]),
            time=record["time"],
            ce_version=record["ce_version"],
            mapping_sha256=mapping["sha256"],
            report=record["report"],
            audit=_identifier(audit["id"]),
            evidence=evidence,
            controls=controls,
            requirements=requirements,
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        raise grc_ledger.LedgerError(
            "The latest complete ledger record has an unexpected shape"
        ) from None


def verify(settings: Settings, say: Say, redactor: Redactor) -> list[str]:
    """Reconcile CISO Assistant with the latest complete ledger record. Raises on drift."""
    mapping = load_mapping(mapping_path(settings))
    ledger = grc_ledger.verify_ledger(grc_ledger.data_folder(settings, redactor))
    for warning in ledger.warnings:
        say(f"WARNING ledger: {warning}")
    latest, failed = grc_ledger.latest_complete(ledger.records)
    if latest is None:
        raise OpsError("The ledger holds no complete push; run `it-grc push` first")
    last = recorded(latest)
    say(
        f"PASS ledger: {len(ledger.records)} record(s) verified; comparing with record"
        f" {last.seq} of {last.time}"
    )
    drift: list[str] = [
        f"ledger record {row['seq']} is a push that failed after {len(row.get('writes') or [])}"
        f" write(s); CISO Assistant may hold changes newer than record {last.seq}"
        for row in failed
    ]
    if last.mapping_sha256 != mapping.sha256:
        drift.append("the mapping file changed since the last push")
    plan = build_plan(mapping, last.report)
    bridge, ctx = prepare(settings, redactor)
    version = ce_version(bridge)
    if version != last.ce_version:
        say(f"NOTE CISO Assistant is {version}; record {last.seq} was written by {last.ce_version}")
    audit = find_audit(ctx)
    if audit is None:
        drift.append(f"audit {AUDIT_REF} is missing")
        return report_drift(drift, say)
    audit_id = object_id(audit)
    if audit_id != last.audit:
        drift.append(f"audit {AUDIT_REF} was replaced by another object")
    if audit.get("is_locked") is True:
        say(f"NOTE audit {AUDIT_REF} is locked")
    evidence = verify_evidence(ctx, plan, last, drift)
    controls = verify_controls(ctx, plan, last, evidence, drift)
    kept = verify_requirements(ctx, plan, audit_id, Links(evidence, controls), last, drift, say)
    audit_summary(ctx, audit_id, say)
    if drift:
        return report_drift(drift, say)
    if kept:
        say(f"{kept} requirement(s) held by human decisions; see the HELD lines above")
    say(
        f"PASS verify: audit {AUDIT_REF}, {len(plan.extracts)} evidence objects and their"
        f" revisions, {len(plan.mapping.controls)} applied control(s) and"
        f" {len(plan.requirements)} requirements match ledger record {last.seq}"
    )
    return []


def report_drift(drift: list[str], say: Say) -> list[str]:
    for item in drift:
        say(f"DRIFT {item}")
    raise DriftError(f"verify found {len(drift)} difference(s) from the ledger")


def reconcile_revisions(
    ref_id: str, then: list[dict[str, Any]], current: list[dict[str, Any]], drift: list[str]
) -> None:
    """Every revision in the ledger still exists unchanged, and no other revision appeared."""
    now = {row["id"]: row for row in current}
    for row in then:
        if row["id"] not in now:
            drift.append(f"evidence {ref_id} revision {row['version']} in the ledger is missing")
        elif now[row["id"]] != row:
            drift.append(
                f"evidence {ref_id} revision {row['version']} changed its version or stored hash"
            )
    known = {row["id"] for row in then}
    for row in current:
        if row["id"] not in known:
            drift.append(f"evidence {ref_id} revision {row['version']} is not in the ledger")


def verify_evidence(
    ctx: Context, plan: Plan, last: Recorded, drift: list[str]
) -> dict[str, str | None]:
    found: dict[str, str | None] = {}
    rows = ctx.bridge.list_all("/evidences/")
    for item in plan.extracts:
        ref_id = item.group.ref_id
        row = by_key(rows, "name", item.group.name, f"evidence {ref_id}")
        if row is None:
            drift.append(f"evidence {ref_id} is missing")
            found[ref_id] = None
            continue
        identifier = in_domain(row, ctx, f"Evidence {ref_id}")
        found[ref_id] = identifier
        current = revision_rows(ctx, identifier)
        known, revisions_then = last.evidence.get(ref_id, (None, []))
        if identifier != known:
            drift.append(f"evidence {ref_id} was replaced by another object")
        else:
            reconcile_revisions(ref_id, revisions_then, current, drift)
        latest = current[-1] if current else {"version": 0, "attachment_hash": None}
        if latest["attachment_hash"] != item.sha256:
            drift.append(
                f"evidence {ref_id} revision {latest['version']} hash"
                f" {latest['attachment_hash']} differs from the local sha256 {item.sha256}"
            )
    return found


def verify_controls(
    ctx: Context,
    plan: Plan,
    last: Recorded,
    evidence: Mapping[str, str | None],
    drift: list[str],
) -> dict[str, str | None]:
    found: dict[str, str | None] = {}
    rows = ctx.bridge.list_all("/applied-controls/")
    for control in plan.mapping.controls:
        row = by_key(rows, "ref_id", control.ref_id, f"applied control {control.ref_id}")
        if row is None:
            drift.append(f"applied control {control.ref_id} is missing")
            found[control.ref_id] = None
            continue
        identifier = in_domain(row, ctx, f"Applied control {control.ref_id}")
        found[control.ref_id] = identifier
        if identifier != last.controls.get(control.ref_id):
            drift.append(f"applied control {control.ref_id} was replaced by another object")
        wanted = {str(evidence[r]) for r in control.evidence if evidence.get(r)}
        if wanted - control_evidence(ctx, identifier):
            drift.append(f"applied control {control.ref_id} lost an evidence link")
    return found


def verify_requirements(  # noqa: PLR0913, PLR0917 - verify context and outputs
    ctx: Context,
    plan: Plan,
    audit: str,
    links: Links,
    last: Recorded,
    drift: list[str],
    say: Say,
) -> int:
    """Drift for every mapped requirement that differs from the plan, unless a human holds it.
    A held row is reported as HELD, with whether the ledger already recorded it. Returns the
    number of held rows."""
    kept = 0
    for planned in plan.requirements:
        target = planned.target
        row = ctx.bridge.requirement_assessment(audit, target.urn)
        observed, reason_then = last.requirements.get(target.urn, (None, None))
        reason = held(row)
        if reason is not None:
            kept += 1
            since = (
                "recorded at the push"
                if reason_then is not None and observed == state(row)
                else "a human decision since the push"
            )
            say(f"HELD {target.urn} ({target.cfr}): {reason}; {since}")
            continue
        for name in sorted(desired(row, planned, links)):
            value = row.get(name)
            listed = name in {"evidences", "applied_controls"}
            shown = f"{len(ids_of(value))} link(s)" if listed else f"{value!s:.40}"
            then = (observed or {}).get(name)
            before = f"the ledger recorded {then}" if then is not None else "plan differs"
            drift.append(f"{target.urn} ({target.cfr}) {name} is {shown}, {before}")
        missing = [r for r in (*target.evidence, *target.supporting) if links.evidence[r] is None]
        if missing:
            drift.append(f"{target.urn} cannot link missing evidence {', '.join(missing)}")
    return kept


# Read-only audit summary


def summary(settings: Settings, say: Say, redactor: Redactor) -> None:
    """What CISO Assistant holds for the lab audit, read with the bridge token. Writes nothing."""
    mapping = load_mapping(mapping_path(settings))
    _, ctx = prepare(settings, redactor)
    audit = find_audit(ctx)
    if audit is None:
        raise OpsError(f"Audit {AUDIT_REF} is missing; run `it-grc push` first")
    audit_id = object_id(audit)
    locked = "locked" if audit.get("is_locked") is True else "not locked"
    status = f"{audit.get('status')!s:.40}"
    say(f"Audit {AUDIT_REF} ({DOMAIN!r} / {PERIMETER_REF}): status {status}, {locked}")
    audit_summary(ctx, audit_id, say)
    rows = ctx.bridge.list_all("/evidences/")
    statuses: Counter[str] = Counter()
    for group in mapping.groups:
        row = by_key(rows, "name", group.name, f"evidence {group.ref_id}")
        if row is None:
            statuses["missing"] += 1
            continue
        in_domain(row, ctx, f"Evidence {group.ref_id}")
        statuses[f"{row.get('status')!s:.40}"] += 1
    say(f"Evidence objects ({len(mapping.groups)}): {counts(statuses)}")
    controls = ctx.bridge.list_all("/applied-controls/")
    for control in mapping.controls:
        row = by_key(controls, "ref_id", control.ref_id, f"applied control {control.ref_id}")
        if row is None:
            say(f"Applied control {control.ref_id}: missing")
            continue
        links = control_evidence(ctx, in_domain(row, ctx, f"Applied control {control.ref_id}"))
        say(
            f"Applied control {control.ref_id}: status {row.get('status')!s:.40},"
            f" {len(links)} evidence link(s)"
        )
    say("Bridge ceiling: partially_compliant / in_review; compliant and done are human decisions")


OPERATIONS: dict[str, Callable[[Settings, Say, Redactor], object]] = {
    "push": push,
    "verify": verify,
    "summary": summary,
}


__all__ = ["OPERATIONS", "DriftError", "MappingError", "guard", "push", "summary", "verify"]
