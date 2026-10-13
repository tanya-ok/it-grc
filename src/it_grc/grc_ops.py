"""Operator commands for the CISO Assistant bridge: bootstrap, rotate-admin, token-refresh
and bridge-check.

Secrets live only in owner-only files under the git-ignored deploy/.data directory. They
are read here, sent to CISO Assistant over TLS and never printed, logged or placed on a
command line. Every printed line passes through a redactor that knows every secret read
or created in the run.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .grc_client import (
    DEFAULT_ORIGIN,
    ClientOptions,
    GrcAuthError,
    GrcClient,
    GrcError,
    GrcHttpError,
    GrcLookupError,
    GrcPermissionError,
    ref,
)
from .grc_mapping import MappingError

ADMIN_EMAIL = "admin@example.org"
BRIDGE_EMAIL = "bridge@example.org"
LIBRARY_URN = "urn:intuitem:risk:library:nist-sp-800-66-rev2"
FRAMEWORK_URN = "urn:intuitem:risk:framework:nist-sp-800-66-rev2"
NODE_PREFIX = "urn:intuitem:risk:req_node:nist-sp-800-66-rev2:"
EXPECTED_ASSESSABLE = 152
DOMAIN = "IT GRC Lab"
DOMAIN_DESCRIPTION = "Synthetic security-lab evidence only. Managed by it-grc bootstrap."
ANALYST_GROUP = f"{DOMAIN} - Analyst"
ANALYST_ROLE = "BI-RL-ANA"
PERIMETER = "Security lab"
PERIMETER_REF = "ITGRC-LAB"
PERIMETER_DESCRIPTION = "Executed scenarios of the local security lab. Synthetic data only."
PROBE_DOMAIN = "IT GRC bridge permission probe"
PAT_NAME = "it-grc-bridge"
TOKEN_DAYS = 1
TOKEN_LIMIT = 5
ADMIN_FILE = "admin-password"
PENDING_FILE = "admin-password.pending"
BRIDGE_LOGIN_FILE = "bridge-password"
BRIDGE_PAT_FILE = "bridge-token"
CA_FILE = "ca.pem"
SECRET_SHAPE = re.compile(r"[A-Za-z0-9_-]{32,256}")
OBJECT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

Say = Callable[[str], None]


class OpsError(Exception):
    """Fixed, secret-free messages."""


class Redactor:
    """Replaces every known secret in text that is about to be printed."""

    def __init__(self) -> None:
        self._values: set[str] = set()

    def add(self, value: str | None) -> None:
        if value:
            self._values.add(value)

    def __call__(self, text: str) -> str:
        for value in sorted(self._values, key=len, reverse=True):
            text = text.replace(value, "<redacted>")
        return text


class Vault:
    """Owner-only secret files in one owner-only directory."""

    def __init__(self, folder: Path, redactor: Redactor) -> None:
        self.folder = folder
        self.redactor = redactor

    def shown(self, name: str) -> str:
        return f"deploy/.data/{name}"

    def directory(self) -> Path:
        if self.folder.is_symlink():
            raise OpsError("deploy/.data must not be a symlink")
        self.folder.mkdir(mode=0o700, exist_ok=True)
        info = self.folder.stat()
        if info.st_uid != os.getuid():
            raise OpsError("deploy/.data is owned by another user")
        if info.st_mode & 0o077:
            self.folder.chmod(0o700)
        return self.folder

    def exists(self, name: str) -> bool:
        path = self.directory() / name
        return path.exists() or path.is_symlink()

    def read(self, name: str) -> str:
        refused = f"Refusing {self.shown(name)}: it must be an owner-only (0600) regular file"
        try:
            descriptor = os.open(self.directory() / name, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            raise OpsError(f"Missing {self.shown(name)}") from None
        except OSError:
            raise OpsError(refused) from None
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise OpsError(refused)
            raw = handle.read(1024)
        value = raw.decode(errors="replace")
        if not SECRET_SHAPE.fullmatch(value):
            raise OpsError(f"{self.shown(name)} has an unexpected format")
        self.redactor.add(value)
        return value

    def _write(self, path: Path, value: str) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value.encode())
            handle.flush()
            os.fsync(handle.fileno())

    def create(self, name: str, value: str) -> None:
        """Write a new file; never overwrite an existing one."""
        if not SECRET_SHAPE.fullmatch(value):
            raise OpsError(f"Refusing to store a malformed value in {self.shown(name)}")
        self.redactor.add(value)
        try:
            self._write(self.directory() / name, value)
        except FileExistsError:
            raise OpsError(f"{self.shown(name)} already exists") from None

    def replace(self, name: str, value: str) -> None:
        """Replace a file atomically through an owner-only temporary file."""
        if not SECRET_SHAPE.fullmatch(value):
            raise OpsError(f"Refusing to store a malformed value in {self.shown(name)}")
        self.redactor.add(value)
        path = self.directory() / name
        temporary = path.with_name(path.name + ".tmp")
        temporary.unlink(missing_ok=True)
        self._write(temporary, value)
        temporary.replace(path)

    def remove(self, name: str) -> None:
        (self.directory() / name).unlink(missing_ok=True)


@dataclass(frozen=True)
class Settings:
    data: Path
    origin: str = DEFAULT_ORIGIN
    options: ClientOptions | None = None
    # Updates the it-grc-bootstrap Secret from the admin password file; returns output lines.
    sync_secret: Callable[[], list[str]] | None = None
    # push and verify (grc_push): the lab report, the mapping file and dry-run mode.
    report: Path | None = None
    mapping: Path | None = None
    dry_run: bool = False


def generate_password() -> str:
    while True:
        value = secrets.token_urlsafe(24)
        if (
            any(c.islower() for c in value)
            and any(c.isupper() for c in value)
            and any(c.isdigit() for c in value)
        ):
            return value


def object_id(row: dict[str, Any]) -> str:
    value = row.get("id")
    if not isinstance(value, str) or not OBJECT_ID.fullmatch(value):
        raise OpsError("An object id has an unexpected shape")
    return value


def connect(settings: Settings, redactor: Redactor) -> tuple[Vault, GrcClient]:
    vault = Vault(settings.data, redactor)
    client = GrcClient(settings.origin, vault.directory() / CA_FILE, options=settings.options)
    return vault, client


def login(client: GrcClient, email: str, password: str, redactor: Redactor) -> GrcClient:
    session = client.login(email, password)
    redactor.add(session.token)
    return session


def try_login(client: GrcClient, email: str, password: str, redactor: Redactor) -> GrcClient | None:
    try:
        return login(client, email, password, redactor)
    except GrcAuthError:
        return None


def admin_session(client: GrcClient, vault: Vault, redactor: Redactor) -> GrcClient:
    session = try_login(client, ADMIN_EMAIL, vault.read(ADMIN_FILE), redactor)
    if session is None:
        raise OpsError(f"The administrator password in {vault.shown(ADMIN_FILE)} was rejected")
    return session


def close(session: GrcClient | None, say: Say) -> None:
    if session is None:
        return
    try:
        session.logout()
    except GrcError:
        say("WARNING: logging out a session failed; it expires on its own")


def token_owner(client: GrcClient, token: str) -> str | None:
    try:
        email = client.with_token(token).current_user().get("email")
    except GrcAuthError:
        return None
    return email if isinstance(email, str) else None


def user_group_ids(user: dict[str, Any]) -> list[str]:
    return sorted(str(ref(group)) for group in user.get("user_groups") or [])


# Bootstrap


def ensure_library(admin: GrcClient, changes: list[str]) -> dict[str, Any]:
    library = admin.stored_library(LIBRARY_URN)
    if library.get("is_loaded") is not True:
        admin.import_library(object_id(library))
        changes.append(f"loaded library {LIBRARY_URN}")
        if admin.stored_library(LIBRARY_URN).get("is_loaded") is not True:
            raise OpsError("The NIST SP 800-66 rev2 library did not load")
    return admin.framework(FRAMEWORK_URN)


def root_folder(client: GrcClient) -> str:
    root = client.one(
        "/folders/",
        {"content_type": "GL"},
        honors={"parent_folder": None},
        match={},
        what="root folder",
    )
    return object_id(root)


def ensure_domain(admin: GrcClient, root: str, changes: list[str]) -> str:
    wanted = {"name": DOMAIN, "parent_folder": root}

    def lookup() -> dict[str, Any] | None:
        return admin.find("/folders/", wanted, honors=wanted, match={}, what="domain")

    domain = lookup()
    if domain is None:
        admin.post(
            "/folders/",
            {
                "name": DOMAIN,
                "description": DOMAIN_DESCRIPTION,
                "parent_folder": root,
                "create_iam_groups": True,
            },
        )
        changes.append(f"created domain {DOMAIN!r} with its IAM groups")
        domain = lookup()
    if domain is None:
        raise GrcLookupError("domain: expected one match, found 0")
    if domain.get("content_type") not in {"DO", "DOMAIN"}:
        raise OpsError(f"{DOMAIN!r} exists but is not a domain; refusing to use it")
    return object_id(domain)


def analyst_group(admin: GrcClient, domain: str, changes: list[str]) -> str:
    def groups() -> list[dict[str, Any]]:
        return admin.select(
            "/user-groups/", {"folder": domain}, honors={"folder": domain}, what="domain groups"
        )

    rows = groups()
    if not rows:
        admin.patch(f"/folders/{domain}/", {"create_iam_groups": True})
        changes.append(f"created the IAM groups of {DOMAIN!r}")
        rows = groups()
    hits = [row for row in rows if row.get("name") == ANALYST_GROUP]
    if len(hits) != 1:
        raise GrcLookupError(f"analyst group: expected one match, found {len(hits)}")
    return object_id(hits[0])


def ensure_perimeter(admin: GrcClient, domain: str, changes: list[str]) -> None:
    # The perimeters endpoint has no ref_id filter: filter by domain, select by ref_id here.
    def lookup() -> dict[str, Any] | None:
        return admin.find(
            "/perimeters/",
            {"folder": domain},
            honors={"folder": domain},
            match={"ref_id": PERIMETER_REF},
            what="perimeter",
        )

    perimeter = lookup()
    if perimeter is None:
        admin.post(
            "/perimeters/",
            {
                "name": PERIMETER,
                "ref_id": PERIMETER_REF,
                "folder": domain,
                "description": PERIMETER_DESCRIPTION,
            },
        )
        changes.append(f"created perimeter {PERIMETER!r} ({PERIMETER_REF})")
        perimeter = lookup()
    if perimeter is None or perimeter.get("name") != PERIMETER:
        raise OpsError(f"Perimeter {PERIMETER_REF} is missing or renamed; refusing to change it")


def ensure_bridge_user(admin: GrcClient, group: str, changes: list[str]) -> str:
    wanted = {"email": BRIDGE_EMAIL}

    def lookup() -> dict[str, Any] | None:
        return admin.find("/users/", wanted, honors=wanted, match={}, what="bridge user")

    user = lookup()
    if user is None:
        admin.post(
            "/users/", {"email": BRIDGE_EMAIL, "first_name": "IT GRC", "last_name": "Bridge"}
        )
        changes.append(f"created user {BRIDGE_EMAIL}")
        user = lookup()
    if user is None:
        raise GrcLookupError("bridge user: expected one match, found 0")
    if user.get("is_superuser") is not False:
        raise OpsError("The bridge user is a superuser; refusing to continue")
    if user.get("is_active") is not True:
        raise OpsError("The bridge user is inactive; refusing to continue")
    if user_group_ids(user) != [group]:
        # Exactly the domain Analyst group: never more, and any other group is removed.
        admin.patch(f"/users/{object_id(user)}/", {"user_groups": [group]})
        changes.append(f"set the groups of {BRIDGE_EMAIL} to {ANALYST_GROUP!r} only")
        user = lookup()
        if user is None or user_group_ids(user) != [group]:
            raise OpsError("The bridge user groups did not change as requested")
    return object_id(user)


def bridge_login(
    admin: GrcClient,
    client: GrcClient,
    vault: Vault,
    user: str,
    changes: list[str],
) -> GrcClient:
    redactor = vault.redactor
    if vault.exists(BRIDGE_LOGIN_FILE):
        password = vault.read(BRIDGE_LOGIN_FILE)
        session = try_login(client, BRIDGE_EMAIL, password, redactor)
        if session is not None:
            return session
        admin.set_password(user, password)
        changes.append(f"set the bridge password from {vault.shown(BRIDGE_LOGIN_FILE)}")
    else:
        password = generate_password()
        vault.create(BRIDGE_LOGIN_FILE, password)
        admin.set_password(user, password)
        changes.append(f"generated the bridge password in {vault.shown(BRIDGE_LOGIN_FILE)}")
    session = try_login(client, BRIDGE_EMAIL, password, redactor)
    if session is None:
        raise OpsError("The bridge user cannot log in after its password was set")
    return session


def issue_bridge_token(client: GrcClient, bridge: GrcClient, vault: Vault) -> int:
    """Create a 1-day token, store it, then revoke every other token of the bridge user.

    Returns the number of revoked tokens."""
    old = vault.read(BRIDGE_PAT_FILE) if vault.exists(BRIDGE_PAT_FILE) else None
    revoked = 0
    existing = bridge.tokens()
    if len(existing) >= TOKEN_LIMIT:
        # CE allows five active tokens per user. All of them belong to this bridge.
        for row in existing:
            bridge.revoke_token(str(row.get("digest")))
            revoked += 1
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    name = f"{PAT_NAME}-{stamp}-{secrets.token_hex(3)}"
    token = bridge.create_token(name, TOKEN_DAYS)
    vault.redactor.add(token)
    if token_owner(client, token) != BRIDGE_EMAIL:
        raise OpsError("The new token does not authenticate as the bridge user")
    vault.replace(BRIDGE_PAT_FILE, token)
    for row in bridge.tokens():
        if row.get("name") != name:
            bridge.revoke_token(str(row.get("digest")))
            revoked += 1
    if [row.get("name") for row in bridge.tokens()] != [name]:
        raise OpsError("The bridge user holds tokens other than the new one")
    if old is not None and old != token and token_owner(client, old) is not None:
        raise OpsError("The previous bridge token still works after revocation")
    return revoked


def ensure_bridge_token(
    client: GrcClient, bridge: GrcClient, vault: Vault, changes: list[str]
) -> None:
    if (
        vault.exists(BRIDGE_PAT_FILE)
        and token_owner(client, vault.read(BRIDGE_PAT_FILE)) == BRIDGE_EMAIL
    ):
        return
    revoked = issue_bridge_token(client, bridge, vault)
    changes.append(
        f"issued a {TOKEN_DAYS}-day bridge token in {vault.shown(BRIDGE_PAT_FILE)}"
        f" and revoked {revoked} other token(s)"
    )


def check_bridge_identity(bridge: GrcClient) -> dict[str, Any]:
    """The token belongs to the bridge user, who holds the Analyst role and nothing else."""
    me = bridge.current_user()
    if (
        me.get("email") != BRIDGE_EMAIL
        or me.get("is_superuser") is not False
        or me.get("is_admin") is not False
        or me.get("roles") != [ANALYST_ROLE]
    ):
        raise OpsError(
            "The bridge token does not belong to a bridge user with only the Analyst role"
        )
    return me


def bootstrap(settings: Settings, say: Say, redactor: Redactor) -> list[str]:
    """Idempotent: library, domain with IAM groups, perimeter, bridge user and token."""
    vault, client = connect(settings, redactor)
    changes: list[str] = []
    admin = admin_session(client, vault, redactor)
    bridge: GrcClient | None = None
    try:
        framework = ensure_library(admin, changes)
        domain = ensure_domain(admin, root_folder(admin), changes)
        group = analyst_group(admin, domain, changes)
        ensure_perimeter(admin, domain, changes)
        user = ensure_bridge_user(admin, group, changes)
        bridge = bridge_login(admin, client, vault, user, changes)
        ensure_bridge_token(client, bridge, vault, changes)
        check_bridge_identity(client.with_token(vault.read(BRIDGE_PAT_FILE)))
    finally:
        close(bridge, say)
        close(admin, say)
    for change in changes:
        say(f"Changed: {change}")
    say(f"Framework {framework.get('urn')} is loaded")
    say(f"Domain {DOMAIN!r}, perimeter {PERIMETER_REF}, user {BRIDGE_EMAIL} in {ANALYST_GROUP!r}")
    say(f"Bridge token (owner-only): {vault.shown(BRIDGE_PAT_FILE)}")
    summary = f"{len(changes)} change(s)" if changes else "no changes"
    say(f"Bootstrap complete: {summary}; administrator session closed")
    return changes


# Administrator password rotation


def resume_rotation(client: GrcClient, vault: Vault, old: str, say: Say) -> str | None:
    """A pending file means an earlier run stopped midway. Returns the pending password if
    the server already accepts it, or None after discarding a rotation that never applied."""
    if not vault.exists(PENDING_FILE):
        return None
    pending = vault.read(PENDING_FILE)
    redactor = vault.redactor
    for password, applied in ((pending, True), (old, False)):
        session = try_login(client, ADMIN_EMAIL, password, redactor)
        if session is not None:
            close(session, say)
            if applied:
                say("Resuming an earlier rotation that already changed the password")
                return pending
            vault.remove(PENDING_FILE)
            say("Discarded an earlier rotation that never changed the password")
            return None
    raise OpsError("Neither the current nor the pending administrator password is accepted")


def rotate_admin(settings: Settings, say: Say, redactor: Redactor) -> None:
    vault, client = connect(settings, redactor)
    old = vault.read(ADMIN_FILE)
    new = resume_rotation(client, vault, old, say)
    if new is None:
        session = admin_session(client, vault, redactor)
        new = generate_password()
        vault.create(PENDING_FILE, new)
        try:
            session.change_password(old, new)
        except GrcHttpError as error:
            if error.status < 500:
                vault.remove(PENDING_FILE)
            close(session, say)
            raise
        close(session, say)
    fresh = try_login(client, ADMIN_EMAIL, new, redactor)
    if fresh is None:
        raise OpsError(f"The new password was not accepted; {vault.shown(PENDING_FILE)} is kept")
    vault.replace(ADMIN_FILE, new)
    vault.remove(PENDING_FILE)
    say(f"Changed the administrator password; stored it in {vault.shown(ADMIN_FILE)}")
    # Every administrator access token, personal tokens included, may stem from the old
    # password. Revoke them all; logoutall also ends the session used here.
    fresh.logout_all()
    stale = try_login(client, ADMIN_EMAIL, old, redactor)
    if stale is not None:
        close(stale, say)
        raise OpsError("The old administrator password still works")
    say("PASS the old administrator password is rejected")
    check = admin_session(client, vault, redactor)
    try:
        leftover = check.tokens()
    finally:
        close(check, say)
    if leftover:
        raise OpsError("The administrator still holds personal access tokens")
    say("PASS the new password logs in; no administrator access token survived the rotation")
    if settings.sync_secret is None:
        raise OpsError("No way to update the bootstrap Secret was configured")
    for line in settings.sync_secret():
        say(line)


# Bridge token refresh and checks


def token_refresh(settings: Settings, say: Say, redactor: Redactor) -> None:
    vault, client = connect(settings, redactor)
    bridge = try_login(client, BRIDGE_EMAIL, vault.read(BRIDGE_LOGIN_FILE), redactor)
    if bridge is None:
        raise OpsError("The bridge password was rejected; run `it-grc bootstrap`")
    try:
        revoked = issue_bridge_token(client, bridge, vault)
    finally:
        close(bridge, say)
    say(f"Issued a {TOKEN_DAYS}-day bridge token in {vault.shown(BRIDGE_PAT_FILE)}")
    say(f"Revoked {revoked} previous token(s); the previous token is rejected")


def expect_denied(action: Callable[[], object], what: str, say: Say) -> None:
    try:
        action()
    except GrcPermissionError:
        say(f"PASS the bridge token cannot {what} (HTTP 403)")
        return
    except GrcHttpError as error:
        raise OpsError(f"Expected HTTP 403 when trying to {what}, got {error.status}") from None
    raise OpsError(f"FAIL: the bridge token could {what}; review its groups now")


def bridge_check(settings: Settings, say: Say, redactor: Redactor) -> None:
    """Read-only checks with the bridge token, plus two writes that must be refused."""
    vault, client = connect(settings, redactor)
    bridge = client.with_token(vault.read(BRIDGE_PAT_FILE))
    check_bridge_identity(bridge)
    say(f"PASS the bridge token authenticates as {BRIDGE_EMAIL} with only the Analyst role")
    visible = sorted(str(row.get("name")) for row in bridge.list_all("/folders/"))
    if not set(visible) <= {"Global", DOMAIN}:
        raise OpsError("The bridge user can see domains other than Global and the lab domain")
    say(f"PASS the bridge user sees only these folders: {', '.join(visible)}")
    framework = bridge.framework(FRAMEWORK_URN)
    nodes = bridge.requirement_nodes(object_id(framework))
    if not nodes or not all(str(node.get("urn")).startswith(NODE_PREFIX) for node in nodes):
        raise OpsError("The requirement nodes do not all belong to NIST SP 800-66 rev2")
    assessable = [node for node in nodes if node.get("assessable") is True]
    if len(assessable) != EXPECTED_ASSESSABLE:
        raise OpsError(f"Expected {EXPECTED_ASSESSABLE} assessable nodes, found {len(assessable)}")
    say(
        f"PASS framework {FRAMEWORK_URN}: {len(nodes)} requirement nodes,"
        f" {len(assessable)} assessable"
    )
    sample = bridge.requirement_node(str(assessable[0].get("urn")))
    say(f"PASS a lookup by URN found exactly one assessable node ({sample.get('urn')})")
    library = object_id(bridge.stored_library(LIBRARY_URN))
    expect_denied(lambda: bridge.import_library(library), "load a library", say)
    expect_denied(lambda: bridge.post("/folders/", {"name": PROBE_DOMAIN}), "create a domain", say)


# Command line


def sync_admin_secret(root: Path) -> list[str]:
    """Run the lifecycle script, which writes the password to the Secret over stdin."""
    script = root / "scripts/grc_lab.py"
    try:
        done = subprocess.run(
            [sys.executable, str(script), "sync-admin-secret"],
            capture_output=True,
            timeout=600,
            check=False,
            cwd=root,
        )
    except (OSError, subprocess.TimeoutExpired):
        done = None
    if done is None or done.returncode:
        raise OpsError(
            "The administrator password changed, but updating the bootstrap Secret failed;"
            " run `make grc-admin-secret`"
        )
    return done.stdout.decode(errors="replace").splitlines()


OPERATIONS: dict[str, Callable[[Settings, Say, Redactor], object]] = {
    "bootstrap": bootstrap,
    "rotate-admin": rotate_admin,
    "token-refresh": token_refresh,
    "bridge-check": bridge_check,
}


MAPPING = "mappings/hipaa-800-66r2.json"


def run(
    command: str,
    root: Path,
    *,
    operations: Mapping[str, Callable[[Settings, Say, Redactor], object]] | None = None,
    report: Path | None = None,
    dry_run: bool = False,
) -> int:
    redactor = Redactor()

    def say(message: str) -> None:
        print(redactor(message), flush=True)

    if not (root / "scripts/grc_lab.py").is_file() or not (root / "deploy").is_dir():
        print("it-grc: CISO Assistant commands need a repository checkout", file=sys.stderr)
        return 2
    settings = Settings(
        data=root / "deploy/.data",
        sync_secret=lambda: sync_admin_secret(root),
        report=report,
        mapping=root / MAPPING,
        dry_run=dry_run,
    )
    try:
        (operations or OPERATIONS)[command](settings, say, redactor)
    except (GrcError, OpsError, MappingError) as error:
        print("it-grc: " + redactor(str(error)), file=sys.stderr)
        return 1
    return 0
