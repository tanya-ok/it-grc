"""Loopback HTTPS servers for the CISO Assistant client tests.

Certificates are generated per test class with the openssl command line tool in a temporary
directory; nothing is stored in the repository. FakeCiso is an in-memory stand-in whose
synthetic responses follow the shapes recorded in the redacted API notes. It is written
for these tests and is not derived from upstream code.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import http.server
import json
import secrets
import shutil
import ssl
import subprocess
import threading
import urllib.parse
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

OPENSSL = shutil.which("openssl")
LIBRARY_URN = "urn:intuitem:risk:library:nist-sp-800-66-rev2"
FRAMEWORK_URN = "urn:intuitem:risk:framework:nist-sp-800-66-rev2"
NODE_PREFIX = "urn:intuitem:risk:req_node:nist-sp-800-66-rev2:"
# Role codes as current-user reports them; only ADM, ANA and DMA were observed live.
ROLES = {
    "Administrator": "BI-RL-ADM",
    "Analyst": "BI-RL-ANA",
    "Approver": "BI-RL-APP",
    "Domain manager": "BI-RL-DMA",
    "Reader": "BI-RL-AUD",
    "Respondent": "BI-RL-RSP",
    "Technical tester": "BI-RL-TTE",
}
LEAF_EXTENSIONS = """basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
"""


@dataclass(frozen=True)
class Certificates:
    ca: Path
    cert: Path
    key: Path


def make_certificates(folder: Path) -> Certificates:
    """A throwaway CA and a leaf for DNS:localhost, valid for two days."""
    assert OPENSSL
    folder.mkdir(parents=True, exist_ok=True)
    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]

    def openssl(*args: str) -> None:
        subprocess.run([OPENSSL, *args], check=True, capture_output=True, timeout=60)

    ca, ca_key = folder / "ca.pem", folder / "ca.key"
    openssl(
        "req", "-x509", *ec, "-days", "2", "-subj", "/CN=it-grc test CA",
        "-keyout", str(ca_key), "-out", str(ca),
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )  # fmt: skip
    request, cert, key = folder / "leaf.csr", folder / "leaf.pem", folder / "leaf.key"
    openssl("req", *ec, "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(request))
    extensions = folder / "leaf.ext"
    extensions.write_text(LEAF_EXTENSIONS)
    openssl(
        "x509", "-req", "-in", str(request), "-CA", str(ca), "-CAkey", str(ca_key),
        "-CAcreateserial", "-days", "2", "-out", str(cert), "-extfile", str(extensions),
    )  # fmt: skip
    return Certificates(ca, cert, key)


@dataclass
class Request:
    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]
    body: Any
    raw: bytes = b""

    def token(self) -> str | None:
        value = self.headers.get("authorization", "")
        return value[6:] if value.startswith("Token ") else None


@dataclass(frozen=True)
class Reply:
    status: int
    payload: Any = None
    content_type: str = "application/json"
    headers: dict[str, str] = field(default_factory=dict)
    raw: bytes | None = None
    reset: bool = False


RESET = Reply(0, reset=True)
App = Callable[[Request], Reply]


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: TlsServer

    def log_message(self, format: str, *args: Any) -> None:
        return

    def dispatch(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        parts = urllib.parse.urlsplit(self.path)
        is_json = (self.headers.get("Content-Type") or "").startswith("application/json")
        request = Request(
            self.command,
            urllib.parse.unquote(parts.path),
            dict(urllib.parse.parse_qsl(parts.query)),
            {key.lower(): value for key, value in self.headers.items()},
            json.loads(raw) if raw and is_json else None,
            raw,
        )
        reply = self.server.app(request)
        if reply.reset:
            # Close without any response; the client sees a connection reset.
            self.close_connection = True
            return
        data = reply.raw
        if data is None:
            data = b"" if reply.payload is None else json.dumps(reply.payload).encode()
        self.send_response(reply.status)
        self.send_header("Content-Type", reply.content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in reply.headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = dispatch  # noqa: N815 - http.server names


class TlsServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, app: App, certificates: Certificates) -> None:
        super().__init__(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificates.cert, certificates.key)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.app = app
        self.thread = threading.Thread(target=self.serve_forever, args=(0.05,), daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def origin(self, host: str = "localhost") -> str:
        return f"https://{host}:{self.port}"

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)


class Script:
    """Replays fixed replies per (method, path) and records every request."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], list[Reply]] = {}
        self.hits: list[Request] = []

    def on(self, method: str, path: str, *replies: Reply) -> None:
        self.routes[(method, path)] = list(replies)

    def __call__(self, request: Request) -> Reply:
        self.hits.append(request)
        replies = self.routes.get((request.method, request.path))
        if not replies:
            return Reply(404, {"detail": "Not found."})
        return replies.pop(0) if len(replies) > 1 else replies[0]

    def count(self, method: str, path: str) -> int:
        return sum(1 for hit in self.hits if (hit.method, hit.path) == (method, path))


def page(rows: list[dict[str, Any]], query: dict[str, str], path: str) -> Reply:
    limit = int(query.get("limit", 100))
    offset = int(query.get("offset", 0))
    chunk = rows[offset : offset + limit]
    following = offset + limit < len(rows)
    nxt = f"{path}?limit={limit}&offset={offset + limit}" if following else None
    return Reply(200, {"count": len(rows), "next": nxt, "previous": None, "results": chunk})


def new_id() -> str:
    return str(uuid.uuid4())


def nested(identifier: str | None, label: str) -> dict[str, str] | None:
    return None if identifier is None else {"id": identifier, "str": label}


def multipart(request: Request) -> tuple[dict[str, str], dict[str, tuple[str, bytes]]]:
    """Text fields and files of a multipart/form-data body."""
    head = f"Content-Type: {request.headers.get('content-type', '')}\r\n\r\n".encode()
    message = email.message_from_bytes(head + request.raw, policy=email.policy.HTTP)
    fields: dict[str, str] = {}
    files: dict[str, tuple[str, bytes]] = {}
    for part in message.iter_parts():  # type: ignore[attr-defined]
        name = part.get_param("name", header="content-disposition")
        payload = part.get_payload(decode=True) or b""
        if part.get_filename():
            files[name] = (part.get_filename(), payload)
        else:
            fields[name] = payload.decode()
    return fields, files


RESULTS = {"not_assessed", "partially_compliant", "non_compliant", "compliant", "not_applicable"}
STATUSES = {"to_do", "in_progress", "in_review", "done"}


class FakeCiso:
    """Stateful stand-in for the subset of the CISO Assistant API the bridge uses."""

    AUTH_PATHS = frozenset(
        {
            "/api/_allauth/app/v1/auth/login",
            "/api/_allauth/app/v1/auth/session",
            "/api/iam/logout/",
            "/api/iam/logoutall/",
        }
    )

    def __init__(self, admin_password: str, nodes: list[dict[str, Any]] | None = None) -> None:
        self.library_nodes = nodes
        self.audits: dict[str, dict[str, Any]] = {}
        self.assessments: dict[str, dict[str, Any]] = {}
        self.evidences: dict[str, dict[str, Any]] = {}
        self.revisions: dict[str, dict[str, Any]] = {}
        self.controls: dict[str, dict[str, Any]] = {}
        # Simulates a server that stores a hash other than the uploaded bytes' SHA-256.
        self.corrupt_hashes = False
        self.users: dict[str, dict[str, Any]] = {}
        self.tokens: dict[str, dict[str, Any]] = {}
        self.sessions: dict[str, str] = {}
        self.folders: dict[str, dict[str, Any]] = {}
        self.groups: dict[str, dict[str, Any]] = {}
        self.perimeters: dict[str, dict[str, Any]] = {}
        self.frameworks: list[dict[str, Any]] = []
        self.nodes: list[dict[str, Any]] = []
        self.library = {"id": new_id(), "urn": LIBRARY_URN, "is_loaded": False}
        self.version = "v4.1.1"
        self.writes: list[tuple[str, str]] = []
        # Every token, session and password the fake handed out or accepted.
        self.issued: list[str] = []
        self.ignored_filters: set[tuple[str, str]] = set()
        self.root = self.add_folder("Global", None, "GLOBAL")
        admin_group = self.add_group("Global - Administrator", self.root)
        self.admin = self.add_user("admin@example.org", admin_password, superuser=True)
        self.users[self.admin]["groups"] = [admin_group]
        self.lock = threading.Lock()

    # State helpers

    def add_folder(self, name: str, parent: str | None, kind: str) -> str:
        identifier = new_id()
        self.folders[identifier] = {
            "id": identifier,
            "name": name,
            "parent_folder": parent,
            "content_type": kind,
        }
        return identifier

    def add_group(self, name: str, folder: str) -> str:
        identifier = new_id()
        self.groups[identifier] = {"id": identifier, "name": name, "folder": folder}
        return identifier

    def add_user(self, email: str, password: str | None, *, superuser: bool = False) -> str:
        identifier = new_id()
        self.users[identifier] = {
            "id": identifier,
            "email": email,
            "password": password,
            "is_superuser": superuser,
            "is_active": True,
            "groups": [],
        }
        return identifier

    def user_by_email(self, email: str) -> dict[str, Any] | None:
        return next((u for u in self.users.values() if u["email"] == email), None)

    def issue(self, user: str, *, name: str | None = None) -> str:
        token = secrets.token_hex(32)
        self.issued.append(token)
        self.tokens[token] = {
            "user": user,
            "pat": name is not None,
            "name": name,
            "digest": secrets.token_hex(64),
            "expiry": "2026-10-14T12:00:00Z",
        }
        return token

    def pats(self, user: str) -> list[dict[str, Any]]:
        return [t for t in self.tokens.values() if t["user"] == user and t["pat"]]

    def load_library(self) -> None:
        framework = new_id()
        self.frameworks.append(
            {"id": framework, "urn": FRAMEWORK_URN, "name": "NIST SP-800-66 rev2 (HIPAA)"}
        )
        if self.library_nodes is not None:
            for row in self.library_nodes:
                self.nodes.append({"id": new_id(), "framework": framework, **row})
            self.library["is_loaded"] = True
            return
        for index in range(179):
            # 27 section nodes, 152 assessable nodes, as in the live library.
            self.nodes.append(
                {
                    "id": new_id(),
                    "urn": f"{NODE_PREFIX}node{index}",
                    "ref_id": f"KA{index}",
                    "assessable": index >= 27,
                    "framework": framework,
                }
            )
        self.library["is_loaded"] = True

    def visible_folders(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        if user["is_superuser"]:
            return list(self.folders.values())
        own = {self.groups[g]["folder"] for g in user["groups"] if g in self.groups}
        return [f for f in self.folders.values() if f["id"] == self.root or f["id"] in own]

    # Rows as the list endpoints show them

    def folder_row(self, folder: dict[str, Any]) -> dict[str, Any]:
        parent = folder["parent_folder"]
        return {
            **folder,
            "parent_folder": nested(parent, self.folders[parent]["name"] if parent else ""),
        }

    def group_row(self, group: dict[str, Any]) -> dict[str, Any]:
        folder = self.folders[group["folder"]]
        return {**group, "builtin": True, "folder": nested(folder["id"], folder["name"])}

    def user_row(self, user: dict[str, Any]) -> dict[str, Any]:
        groups = [nested(g, self.groups[g]["name"]) for g in user["groups"]]
        row = {k: v for k, v in user.items() if k not in {"password", "groups"}}
        return {**row, "user_groups": groups}

    def filtered(
        self, path: str, rows: list[dict[str, Any]], query: dict[str, str], keys: dict[str, str]
    ) -> list[dict[str, Any]]:
        for name, key in keys.items():
            if name in query and (path, name) not in self.ignored_filters:
                rows = [r for r in rows if str(r.get(key)) == query[name]]
        return rows

    # Request handling

    def __call__(self, request: Request) -> Reply:
        with self.lock:
            if request.method != "GET" and request.path not in self.AUTH_PATHS:
                self.writes.append((request.method, request.path))
            return self.handle(request)

    def handle(self, request: Request) -> Reply:  # noqa: PLR0911, PLR0912 - flat router
        method, path, body = request.method, request.path, request.body or {}
        if (method, path) == ("POST", "/api/_allauth/app/v1/auth/login"):
            return self.login(body)
        if (method, path) == ("DELETE", "/api/_allauth/app/v1/auth/session"):
            gone = self.sessions.pop(request.headers.get("x-session-token", ""), None)
            return Reply(401 if gone else 410, {"status": 401 if gone else 410, "meta": {}})
        token = request.token()
        if token is None or token not in self.tokens:
            return Reply(401, {"detail": "Invalid token."})
        user = self.users[self.tokens[token]["user"]]
        admin = bool(user["is_superuser"])
        query = request.query
        if (method, path) == ("POST", "/api/iam/logout/"):
            del self.tokens[token]
            return Reply(204)
        if (method, path) == ("POST", "/api/iam/logoutall/"):
            for key in [k for k, v in self.tokens.items() if v["user"] == user["id"]]:
                del self.tokens[key]
            return Reply(204)
        if (method, path) == ("GET", "/api/iam/current-user/"):
            roles = sorted(
                {ROLES[self.groups[g]["name"].rsplit(" - ", 1)[1]] for g in user["groups"]}
            )
            me = {"email": user["email"], "is_superuser": admin, "is_admin": admin, "roles": roles}
            return Reply(200, me)
        if (method, path) == ("GET", "/api/build/"):
            return Reply(200, {"version": self.version, "build": "synthetic"})
        if (method, path) == ("POST", "/api/iam/change-password/"):
            if body.get("old_password") != user["password"]:
                return Reply(400, {"non_field_errors": ["Your old password was incorrect."]})
            user["password"] = body["new_password"]
            self.issued.append(body["new_password"])
            return Reply(200)
        if (method, path) == ("POST", "/api/iam/set-password/"):
            if not admin:
                return Reply(403, {"detail": "Forbidden"})
            self.users[body["user"]]["password"] = body["new_password"]
            self.issued.append(body["new_password"])
            return Reply(200)
        if path.startswith("/api/iam/auth-tokens/"):
            return self.auth_tokens(method, path, user, body)
        if path == "/api/stored-libraries/":
            return page(self.filtered(path, [self.library], query, {"urn": "urn"}), query, path)
        if method == "POST" and path == f"/api/stored-libraries/{self.library['id']}/import/":
            if not admin:
                return Reply(403, {"detail": "You do not have permission."})
            if self.library["is_loaded"]:
                return Reply(400, {"error": "libraryAlreadyLoadedError"})
            self.load_library()
            return Reply(200, {"status": "success"})
        if path == "/api/frameworks/":
            return page(self.frameworks, query, path)  # no URN filter exists
        if path == "/api/requirement-nodes/":
            keys = {"urn": "urn", "framework": "framework"}
            return page(self.filtered(path, self.nodes, query, keys), query, path)
        if path.startswith("/api/folders/"):
            return self.folders_route(method, path, user, body, query)
        if path.startswith("/api/compliance-assessments/"):
            return self.audits_route(method, path, user, body, query)
        if path.startswith("/api/requirement-assessments/"):
            return self.assessments_route(method, path, user, body, query)
        if path.startswith("/api/evidences/"):
            return self.evidences_route(method, path, user, body, query)
        if path.startswith("/api/evidence-revisions/"):
            return self.revisions_route(method, request, user, query)
        if path.startswith("/api/applied-controls/"):
            return self.controls_route(method, path, user, body, query)
        if path == "/api/user-groups/":
            rows = [self.group_row(g) for g in self.groups.values()]
            rows = [
                r for r in rows if "folder" not in query or r["folder"]["id"] == query["folder"]
            ]
            return page(rows, query, path)
        if path == "/api/perimeters/":
            return self.perimeters_route(method, path, user, body, query)
        if path.startswith("/api/users/"):
            if not admin:
                return Reply(403, {"detail": "Forbidden"})
            return self.users_route(method, path, body, query)
        return Reply(404, {"detail": "Not found."})

    def login(self, body: dict[str, Any]) -> Reply:
        user = self.user_by_email(str(body.get("email")))
        if (
            user is None
            or user["password"] is None
            or user["password"] != body.get("password")
            or not user["is_active"]
        ):
            return Reply(400, {"status": 400, "errors": [{"code": "email_password_mismatch"}]})
        session = secrets.token_hex(16)
        self.issued.append(session)
        self.sessions[session] = user["id"]
        meta = {
            "access_token": self.issue(user["id"]),
            "session_token": session,
            "is_authenticated": True,
        }
        return Reply(200, {"status": 200, "data": {"user": {"email": user["email"]}}, "meta": meta})

    def auth_tokens(
        self, method: str, path: str, user: dict[str, Any], body: dict[str, Any]
    ) -> Reply:
        if method == "GET":
            rows = [
                {
                    "name": t["name"],
                    "user": {"id": user["id"], "email": user["email"]},
                    "expiry": t["expiry"],
                    "digest": t["digest"],
                }
                for t in self.pats(user["id"])
            ]
            return Reply(200, rows)
        if method == "POST":
            if len(self.pats(user["id"])) >= 5:
                return Reply(403, {"error": "errorMaxPatAmountExceeded"})
            token = self.issue(user["id"], name=str(body.get("name")))
            return Reply(
                200, {"expiry": "2026-10-14T12:00:00Z", "name": body["name"], "token": token}
            )
        digest = path.rstrip("/").rsplit("/", 1)[-1]
        for key, value in list(self.tokens.items()):
            if value["digest"] == digest and value["user"] == user["id"]:
                del self.tokens[key]
                return Reply(204)
        return Reply(404, {"error": "Token not found or already deleted."})

    def folders_route(
        self,
        method: str,
        path: str,
        user: dict[str, Any],
        body: dict[str, Any],
        query: dict[str, str],
    ) -> Reply:
        if method == "GET" and path == "/api/folders/":
            rows = [self.folder_row(f) for f in self.visible_folders(user)]
            if "content_type" in query:
                kinds = {"GL": "GLOBAL", "DO": "DOMAIN"}
                rows = [r for r in rows if r["content_type"] == kinds.get(query["content_type"])]
            if "name" in query and (path, "name") not in self.ignored_filters:
                rows = [r for r in rows if r["name"] == query["name"]]
            if "parent_folder" in query:
                rows = [
                    r
                    for r in rows
                    if (r["parent_folder"] or {}).get("id") == query["parent_folder"]
                ]
            return page(rows, query, path)
        if not user["is_superuser"]:
            return Reply(
                403, {"folder": "You do not have permission to add objects in this folder"}
            )
        if method == "POST" and path == "/api/folders/":
            folder = self.add_folder(body["name"], body.get("parent_folder") or self.root, "DOMAIN")
            if body.get("create_iam_groups"):
                self.create_groups(folder)
            return Reply(201, {"id": folder, "name": body["name"], "content_type": "DO"})
        identifier = path.rstrip("/").rsplit("/", 1)[-1]
        if method == "PATCH" and identifier in self.folders:
            if body.get("create_iam_groups"):
                self.create_groups(identifier)
            return Reply(200, {"id": identifier})
        return Reply(404, {"detail": "Not found."})

    def create_groups(self, folder: str) -> None:
        if not any(g["folder"] == folder for g in self.groups.values()):
            for role in list(ROLES)[1:]:
                self.add_group(f"{self.folders[folder]['name']} - {role}", folder)

    def perimeters_route(
        self,
        method: str,
        path: str,
        user: dict[str, Any],
        body: dict[str, Any],
        query: dict[str, str],
    ) -> Reply:
        if method == "POST":
            if not user["is_superuser"]:
                return Reply(403, {"detail": "Forbidden"})
            identifier = new_id()
            self.perimeters[identifier] = {
                "id": identifier,
                "name": body["name"],
                "ref_id": body.get("ref_id"),
                "folder": body["folder"],
            }
            return Reply(201, self.perimeters[identifier])
        rows = [
            {**p, "folder": nested(p["folder"], self.folders[p["folder"]]["name"])}
            for p in self.perimeters.values()
        ]
        if "folder" in query:
            rows = [r for r in rows if r["folder"]["id"] == query["folder"]]
        return page(rows, query, path)  # ref_id is not a filter of this endpoint

    def users_route(
        self, method: str, path: str, body: dict[str, Any], query: dict[str, str]
    ) -> Reply:
        if method == "GET" and path == "/api/users/":
            rows = [self.user_row(u) for u in self.users.values()]
            return page(self.filtered(path, rows, query, {"email": "email"}), query, path)
        if method == "POST" and path == "/api/users/":
            identifier = self.add_user(body["email"], None)
            return Reply(201, self.user_row(self.users[identifier]))
        identifier = path.rstrip("/").rsplit("/", 1)[-1]
        if method == "PATCH" and identifier in self.users:
            if "user_groups" in body:
                self.users[identifier]["groups"] = list(body["user_groups"])
            return Reply(200, self.user_row(self.users[identifier]))
        return Reply(404, {"detail": "Not found."})

    # Audits, evidence and applied controls

    def may_write(self, user: dict[str, Any], folder: str | None) -> bool:
        if user["is_superuser"]:
            return True
        return any(self.groups[g]["folder"] == folder for g in user["groups"] if g in self.groups)

    def label(self, kind: dict[str, dict[str, Any]], identifier: str) -> dict[str, str] | None:
        row = kind.get(identifier)
        return nested(identifier, str(row.get("name") or row.get("ref_id"))) if row else None

    def audit_row(self, audit: dict[str, Any]) -> dict[str, Any]:
        folder = self.folders[audit["folder"]]
        return {
            **audit,
            "folder": nested(folder["id"], folder["name"]),
            "perimeter": nested(audit["perimeter"], "perimeter"),
            "framework": nested(audit["framework"], "framework"),
        }

    def assessment_row(self, row: dict[str, Any]) -> dict[str, Any]:
        node = next(n for n in self.nodes if n["id"] == row["requirement"])
        return {
            **row,
            "compliance_assessment": nested(row["compliance_assessment"], "audit"),
            "folder": nested(row["folder"], self.folders[row["folder"]]["name"]),
            "requirement": {"id": node["id"], "urn": node["urn"], "assessable": node["assessable"]},
            "evidences": [self.label(self.evidences, e) for e in row["evidences"]],
            "applied_controls": [self.label(self.controls, c) for c in row["applied_controls"]],
        }

    def folder_of(self, row: dict[str, Any]) -> dict[str, Any]:
        folder = self.folders[row["folder"]]
        return {**row, "folder": nested(folder["id"], folder["name"])}

    def visible(self, user: dict[str, Any], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        folders = {f["id"] for f in self.visible_folders(user)}
        return [row for row in rows if row["folder"] in folders]

    def honored(
        self, path: str, rows: list[dict[str, Any]], query: dict[str, str], keys: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Filter raw rows by id-valued keys unless the filter is set to be ignored."""
        for name, key in keys.items():
            if name in query and (path, name) not in self.ignored_filters:
                rows = [r for r in rows if str(r.get(key)) == query[name]]
        return rows

    def audits_route(
        self,
        method: str,
        path: str,
        user: dict[str, Any],
        body: dict[str, Any],
        query: dict[str, str],
    ) -> Reply:
        base = "/api/compliance-assessments/"
        if method == "GET" and path == base:
            rows = self.honored(
                base,
                self.visible(user, list(self.audits.values())),
                query,
                {"ref_id": "ref_id", "perimeter": "perimeter", "folder": "folder"},
            )
            return page([self.audit_row(r) for r in rows], query, path)
        if method == "POST" and path == base:
            perimeter = self.perimeters.get(body.get("perimeter", ""))
            if perimeter is None or not self.may_write(user, perimeter["folder"]):
                return Reply(403, {"detail": "Forbidden"})
            identifier = new_id()
            self.audits[identifier] = {
                "id": identifier,
                "name": body["name"],
                "ref_id": body.get("ref_id", ""),
                "description": body.get("description", ""),
                "folder": perimeter["folder"],
                "perimeter": perimeter["id"],
                "framework": body["framework"],
                "status": body.get("status", "planned"),
                "is_locked": False,
            }
            for node in self.nodes:
                if node["framework"] != body["framework"]:
                    continue
                key = new_id()
                self.assessments[key] = {
                    "id": key,
                    "compliance_assessment": identifier,
                    "folder": perimeter["folder"],
                    "requirement": node["id"],
                    "assessable": node["assessable"],
                    "result": "not_assessed",
                    "status": "to_do",
                    "observation": "",
                    "extended_result": None,
                    "evidences": [],
                    "applied_controls": [],
                    "is_locked": False,
                    "review_state": "",
                }
            return Reply(201, self.audit_row(self.audits[identifier]))
        parts = path[len(base) :].strip("/").split("/")
        audit = self.audits.get(parts[0])
        if method == "GET" and audit and parts[1:] == ["evidence_coverage"]:
            rows = [
                a for a in self.assessments.values() if a["compliance_assessment"] == audit["id"]
            ]
            covered = sum(1 for a in rows if a["assessable"] and a["evidences"])
            total = sum(1 for a in rows if a["assessable"])
            return Reply(200, {"total": total, "covered": covered, "uncovered": total - covered})
        return Reply(404, {"detail": "Not found."})

    def assessments_route(
        self,
        method: str,
        path: str,
        user: dict[str, Any],
        body: dict[str, Any],
        query: dict[str, str],
    ) -> Reply:
        base = "/api/requirement-assessments/"
        if method == "GET" and path == base:
            rows = self.honored(
                base,
                self.visible(user, list(self.assessments.values())),
                query,
                {"compliance_assessment": "compliance_assessment"},
            )
            if (
                "requirement__urn" in query
                and (base, "requirement__urn") not in self.ignored_filters
            ):
                ids = {n["id"] for n in self.nodes if n["urn"] == query["requirement__urn"]}
                rows = [r for r in rows if r["requirement"] in ids]
            return page([self.assessment_row(r) for r in rows], query, path)
        row = self.assessments.get(path[len(base) :].strip("/"))
        if method == "PATCH" and row is not None:
            if not self.may_write(user, row["folder"]):
                return Reply(403, {"detail": "Forbidden"})
            if (
                body.get("result", "not_assessed") not in RESULTS
                or body.get("status", "to_do") not in STATUSES
            ):
                return Reply(400, {"detail": "invalid choice"})
            row.update(body)
            return Reply(200, self.assessment_row(row))
        return Reply(404, {"detail": "Not found."})

    def evidences_route(
        self,
        method: str,
        path: str,
        user: dict[str, Any],
        body: dict[str, Any],
        query: dict[str, str],
    ) -> Reply:
        base = "/api/evidences/"
        if method == "GET" and path == base:
            rows = self.honored(
                base,
                self.visible(user, list(self.evidences.values())),
                query,
                {"folder": "folder", "name": "name"},
            )
            return page([self.folder_of(r) for r in rows], query, path)
        if method == "POST" and path == base:
            if not self.may_write(user, body.get("folder")):
                return Reply(403, {"detail": "Forbidden"})
            identifier = new_id()
            self.evidences[identifier] = {
                "id": identifier,
                "name": body["name"],
                "description": body.get("description", ""),
                "folder": body["folder"],
                "status": "draft",
            }
            return Reply(201, self.folder_of(self.evidences[identifier]))
        return Reply(404, {"detail": "Not found."})

    def revisions_route(
        self, method: str, request: Request, user: dict[str, Any], query: dict[str, str]
    ) -> Reply:
        base = "/api/evidence-revisions/"
        if method == "GET" and request.path == base:
            rows = self.honored(
                base,
                self.visible(user, list(self.revisions.values())),
                query,
                {"evidence": "evidence"},
            )
            shown = [
                {
                    **{k: v for k, v in self.folder_of(r).items() if k != "content"},
                    "evidence": self.label(self.evidences, r["evidence"]),
                }
                for r in rows
            ]
            return page(shown, query, request.path)
        if method == "POST" and request.path == base:
            fields, files = multipart(request)
            evidence = self.evidences.get(fields.get("evidence", ""))
            if evidence is None or "attachment" not in files:
                return Reply(400, {"detail": "invalid"})
            if not self.may_write(user, evidence["folder"]):
                return Reply(403, {"detail": "Forbidden"})
            name, content = files["attachment"]
            evidence["status"] = "in_review"
            digest = hashlib.sha256(content).hexdigest()
            versions = [
                r["version"] for r in self.revisions.values() if r["evidence"] == evidence["id"]
            ]
            identifier = new_id()
            self.revisions[identifier] = {
                "id": identifier,
                "evidence": evidence["id"],
                "folder": evidence["folder"],
                "version": max(versions, default=0) + 1,
                "attachment": name,
                "attachment_hash": ("0" * 64) if self.corrupt_hashes else digest,
                "original_filename": name,
                "observation": fields.get("observation", ""),
                "content": content,
            }
            row = {k: v for k, v in self.revisions[identifier].items() if k != "content"}
            return Reply(201, row)
        return Reply(404, {"detail": "Not found."})

    def controls_route(  # noqa: PLR0911 - flat router
        self,
        method: str,
        path: str,
        user: dict[str, Any],
        body: dict[str, Any],
        query: dict[str, str],
    ) -> Reply:
        base = "/api/applied-controls/"
        if method == "GET" and path == base:
            rows = self.honored(
                base,
                self.visible(user, list(self.controls.values())),
                query,
                {"folder": "folder", "ref_id": "ref_id"},
            )
            # As in CE v4.1.1, list rows of applied controls carry no evidence links.
            shown = [{k: v for k, v in self.folder_of(r).items() if k != "evidences"} for r in rows]
            return page(shown, query, path)
        if method == "POST" and path == base:
            if not self.may_write(user, body.get("folder")):
                return Reply(403, {"detail": "Forbidden"})
            identifier = new_id()
            self.controls[identifier] = {
                "id": identifier,
                "status": "--",
                **{k: v for k, v in body.items() if k != "evidences"},
                "evidences": list(body.get("evidences") or []),
            }
            return Reply(201, self.folder_of(self.controls[identifier]))
        row = self.controls.get(path[len(base) :].strip("/"))
        if method == "GET" and row is not None:
            evidences = [self.label(self.evidences, e) for e in row["evidences"]]
            return Reply(200, {**self.folder_of(row), "evidences": evidences})
        if method == "PATCH" and row is not None:
            if not self.may_write(user, row["folder"]):
                return Reply(403, {"detail": "Forbidden"})
            row.update(body)
            return Reply(200, self.folder_of(row))
        return Reply(404, {"detail": "Not found."})
