"""Standard-library REST client for CISO Assistant Community edition.

Safety rules (see docs/bridge.md):

- HTTPS only. The SSLContext trusts only the given CA file and verifies host names.
- No proxies and no redirects: the opener has no proxy, redirect, plain HTTP or file handler.
- JSON only, a bounded response size and explicit timeouts. The single exception on the
  request side is the multipart upload of an evidence revision; responses stay JSON only.
- Retries with backoff on HTTP 5xx and connection resets only, and only for GET, PUT and
  DELETE. POST and PATCH are never repeated.
- Error messages are fixed text. They never contain response bodies, tokens or passwords.
- The API silently ignores unknown query filters, so every lookup that targets one object
  checks the returned fields itself and asserts exactly one match.
"""

from __future__ import annotations

import copy
import http.client
import json
import re
import secrets
import ssl
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_ORIGIN = "https://localhost:18443"
API = "/api"
LOGIN = "/_allauth/app/v1/auth/login"
SESSION = "/_allauth/app/v1/auth/session"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
PAGE_SIZE = 100
MAX_PAGES = 200
RETRY_METHODS = frozenset({"GET", "PUT", "DELETE"})
SECRET_SHAPE = re.compile(r"[A-Za-z0-9_-]{32,256}")
FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
FORM_FIELD = re.compile(r"[a-z_]{1,40}")
ORIGIN_SHAPE = re.compile(
    r"https://(localhost|\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9.-]+\.[a-z]{2,}):(\d{1,5})"
)
# Path segments shown in error messages. Anything else (ids, URNs, token digests) becomes {id}.
ROUTE_WORDS = frozenset(
    {
        "",
        "_allauth",
        "app",
        "v1",
        "auth",
        "login",
        "session",
        "api",
        "iam",
        "auth-tokens",
        "current-user",
        "logout",
        "logoutall",
        "change-password",
        "set-password",
        "folders",
        "perimeters",
        "users",
        "user-groups",
        "stored-libraries",
        "loaded-libraries",
        "import",
        "frameworks",
        "requirement-nodes",
        "requirement-assessments",
        "compliance-assessments",
        "evidences",
        "evidence-revisions",
        "evidence_coverage",
        "applied-controls",
        "build",
        "health",
    }
)


class GrcError(Exception):
    """Base error. Messages are fixed text without response bodies or secrets."""


class GrcConfigError(GrcError):
    """Invalid client configuration, such as a missing CA file or a non-HTTPS origin."""


class GrcTransportError(GrcError):
    """The server could not be reached, or TLS verification failed."""


class GrcRedirectError(GrcError):
    """The server answered with a redirect. Redirects are never followed."""


class GrcResponseError(GrcError):
    """The response was too large, not JSON or not shaped as expected."""


class GrcLookupError(GrcError):
    """A lookup did not resolve to exactly one matching object."""


class GrcHttpError(GrcError):
    """A non-success HTTP status. Only the method, a redacted route and the status are kept."""

    def __init__(self, method: str, path: str, status: int) -> None:
        self.method = method
        self.route = route(path)
        self.status = status
        super().__init__(f"{method} {self.route} answered HTTP {status}")


class GrcAuthError(GrcHttpError):
    """HTTP 401, or a rejected login."""


class GrcPermissionError(GrcHttpError):
    """HTTP 403."""


class GrcNotFoundError(GrcHttpError):
    """HTTP 404."""


def route(path: str) -> str:
    """The path without its query, with every unknown segment replaced by {id}."""
    parts = urllib.parse.urlsplit(path).path.split("/")
    return "/".join(part if part in ROUTE_WORDS else "{id}" for part in parts)


def http_error(method: str, path: str, status: int) -> GrcHttpError:
    kinds: dict[int, type[GrcHttpError]] = {
        401: GrcAuthError,
        403: GrcPermissionError,
        404: GrcNotFoundError,
    }
    return kinds.get(status, GrcHttpError)(method, path, status)


def tls_context(ca_file: Path) -> ssl.SSLContext:
    """A client context that trusts only `ca_file` and verifies host names."""
    try:
        info = ca_file.lstat()
    except OSError:
        raise GrcConfigError("CA certificate file is missing") from None
    if not stat.S_ISREG(info.st_mode):
        raise GrcConfigError("CA certificate file must be a regular file")
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_file))
    except (ssl.SSLError, OSError, ValueError):
        raise GrcConfigError("CA certificate file is not a valid PEM certificate") from None
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if not context.get_ca_certs():
        raise GrcConfigError("CA certificate file holds no CA certificate")
    return context


def build_opener(context: ssl.SSLContext) -> urllib.request.OpenerDirector:
    """HTTPS only, without proxy, redirect, plain HTTP, file, FTP or data handlers."""
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener


def check_origin(origin: str) -> str:
    match = ORIGIN_SHAPE.fullmatch(origin)
    if not match or not 0 < int(match.group(2)) < 65536:
        raise GrcConfigError("The origin must be https://<host>:<port> without a path")
    return origin


def check_secret(value: object) -> str:
    if not isinstance(value, str) or not SECRET_SHAPE.fullmatch(value):
        raise GrcResponseError("The server returned a credential of an unexpected shape")
    return value


def ref(value: Any) -> Any:
    """The id of a nested `{"id": ..., "str": ...}` reference, or the value itself."""
    if isinstance(value, dict) and "id" in value:
        return value["id"]
    return value


def field_value(row: Mapping[str, Any], name: str) -> Any:
    value: Any = row
    for part in name.split("."):
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value


def same(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, dict):
        actual = ref(actual)
    return type(actual) is type(expected) and actual == expected


def matches(row: Mapping[str, Any], wanted: Mapping[str, Any]) -> bool:
    return all(same(field_value(row, key), value) for key, value in wanted.items())


@dataclass(frozen=True)
class ClientOptions:
    timeout: float = 30.0
    max_bytes: int = MAX_RESPONSE_BYTES
    retry_delays: tuple[float, ...] = (0.5, 1.0, 2.0)
    sleep: Callable[[float], None] = field(default=time.sleep)


class GrcClient:
    """One origin, one trusted CA and at most one access token."""

    def __init__(self, origin: str, ca_file: Path, *, options: ClientOptions | None = None) -> None:
        self.origin = check_origin(origin)
        self.options = options or ClientOptions()
        self._opener = build_opener(tls_context(ca_file))
        self._token: str | None = None
        self._session: str | None = None

    def __repr__(self) -> str:
        return f"GrcClient(origin={self.origin!r}, authenticated={self._token is not None})"

    @property
    def token(self) -> str | None:
        return self._token

    def with_token(self, token: str, session: str | None = None) -> GrcClient:
        """A client that shares the opener and sends `token`."""
        clone = copy.copy(self)
        clone._token = check_secret(token)
        clone._session = check_secret(session) if session is not None else None
        return clone

    # Transport

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str | int] | None = None,
        body: Any = None,
        timeout: float | None = None,
    ) -> Any:
        """Send one JSON request and return the decoded JSON body, or None when empty."""
        data = None if body is None else json.dumps(body).encode()
        return self._send(
            method,
            path,
            params=params,
            data=data,
            content_type="application/json",
            timeout=timeout or self.options.timeout,
            extra={},
        )

    def post_form(  # noqa: PLR0913 - one multipart file with its metadata
        self,
        path: str,
        fields: Mapping[str, str],
        *,
        file_field: str,
        file_name: str,
        content: bytes,
        file_type: str = "application/json",
    ) -> Any:
        """POST one multipart/form-data request with text fields and one file.

        Used for evidence revisions, which carry an attachment. Like every POST it is never
        repeated, so a revision is never created twice by a retry."""
        if not FILE_NAME.fullmatch(file_name) or not all(
            FORM_FIELD.fullmatch(name) for name in [*fields, file_field]
        ):
            raise GrcConfigError("Invalid multipart field or file name")
        boundary = "it-grc-" + secrets.token_hex(16)
        if boundary.encode() in content or any(boundary in value for value in fields.values()):
            raise GrcConfigError("Multipart boundary collision")
        parts: list[bytes] = []
        for name, value in fields.items():
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
                + value.encode()
                + b"\r\n"
            )
        parts.append(
            (
                f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}";'
                f' filename="{file_name}"\r\nContent-Type: {file_type}\r\n\r\n'
            ).encode()
            + content
            + b"\r\n"
        )
        parts.append(f"--{boundary}--\r\n".encode())
        return self._send(
            "POST",
            path,
            params=None,
            data=b"".join(parts),
            content_type=f"multipart/form-data; boundary={boundary}",
            timeout=self.options.timeout,
            extra={},
        )

    def _url(self, path: str, params: Mapping[str, str | int] | None) -> str:
        if not path.startswith("/") or path.startswith("//") or ".." in path or "?" in path:
            raise GrcConfigError("Invalid API path")
        query = "?" + urllib.parse.urlencode(params) if params else ""
        return self.origin + API + urllib.parse.quote(path, safe="/:@-._~") + query

    def _send(  # noqa: PLR0913 - internal transport entry point
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str | int] | None,
        data: bytes | None,
        content_type: str,
        timeout: float,
        extra: Mapping[str, str],
    ) -> Any:
        url = self._url(path, params)
        attempts = 1 + (len(self.options.retry_delays) if method in RETRY_METHODS else 0)
        for attempt in range(attempts):
            request = urllib.request.Request(url, data=data, method=method)
            request.add_header("Accept", "application/json")
            if data is not None:
                request.add_header("Content-Type", content_type)
            if self._token:
                request.add_unredirected_header("Authorization", "Token " + self._token)
            for key, value in extra.items():
                request.add_unredirected_header(key, value)
            retry = attempt + 1 < attempts
            try:
                with self._opener.open(request, timeout=timeout) as response:
                    return self._decode(method, path, response.status, response)
            except urllib.error.HTTPError as error:
                with error:
                    status = error.code
                if 500 <= status < 600 and retry:
                    self.options.sleep(self.options.retry_delays[attempt])
                    continue
                if 300 <= status < 400:
                    raise GrcRedirectError(
                        f"{method} {route(path)} answered a redirect; redirects are not followed"
                    ) from None
                raise http_error(method, path, status) from None
            except (urllib.error.URLError, OSError, http.client.HTTPException) as error:
                reason = getattr(error, "reason", error)
                if isinstance(reason, ConnectionResetError) and retry:
                    self.options.sleep(self.options.retry_delays[attempt])
                    continue
                if isinstance(reason, ssl.SSLCertVerificationError):
                    raise GrcTransportError(
                        "TLS verification failed: the server certificate or host name "
                        "does not match the trusted CA"
                    ) from None
                raise GrcTransportError(f"{method} {route(path)} could not be completed") from None
        raise GrcTransportError(f"{method} {route(path)} could not be completed")

    def _decode(self, method: str, path: str, status: int, response: Any) -> Any:
        if not 200 <= status < 300:
            raise http_error(method, path, status)
        length = response.headers.get("Content-Length")
        if length and length.isdigit() and int(length) > self.options.max_bytes:
            raise GrcResponseError(f"{method} {route(path)} response exceeds the size limit")
        raw = response.read(self.options.max_bytes + 1)
        if len(raw) > self.options.max_bytes:
            raise GrcResponseError(f"{method} {route(path)} response exceeds the size limit")
        if not raw.strip():
            return None
        if response.headers.get_content_type() != "application/json":
            raise GrcResponseError(f"{method} {route(path)} did not answer with JSON")
        try:
            return json.loads(raw)
        except ValueError:
            raise GrcResponseError(f"{method} {route(path)} answered invalid JSON") from None

    def get(self, path: str, params: Mapping[str, str | int] | None = None) -> Any:
        return self.request("GET", path, params=params)

    def post(self, path: str, body: Any = None, *, timeout: float | None = None) -> Any:
        return self.request("POST", path, body=body, timeout=timeout)

    def patch(self, path: str, body: Any) -> Any:
        return self.request("PATCH", path, body=body)

    def delete(self, path: str) -> None:
        self.request("DELETE", path)

    # Authentication

    def login(self, email: str, password: str) -> GrcClient:
        """Log in through the headless flow; the returned client holds the session."""
        try:
            answer = self.request("POST", LOGIN, body={"email": email, "password": password})
        except GrcHttpError as error:
            if error.status in {400, 401, 403, 409}:
                raise GrcAuthError("POST", LOGIN, error.status) from None
            raise
        meta = obj(answer, "login").get("meta")
        if not isinstance(meta, dict) or meta.get("is_authenticated") is not True:
            raise GrcResponseError("Login answered without an authenticated session")
        session = meta.get("session_token")
        return self.with_token(
            check_secret(meta.get("access_token")),
            check_secret(session) if session is not None else None,
        )

    def logout(self) -> None:
        """Delete the access token in use and end the headless session, if any.

        For a personal access token this revokes the token itself.
        """
        session = self._session
        if self._token is None:
            return
        try:
            self.request("POST", "/iam/logout/")
        finally:
            self._token = self._session = None
            if session is not None:
                self._end_session(session)

    def logout_all(self) -> None:
        """Delete every access token of the current user, personal access tokens included."""
        session = self._session
        try:
            self.request("POST", "/iam/logoutall/")
        finally:
            self._token = self._session = None
            if session is not None:
                self._end_session(session)

    def _end_session(self, session: str) -> None:
        try:
            self._send(
                "DELETE",
                SESSION,
                params=None,
                data=None,
                content_type="application/json",
                timeout=self.options.timeout,
                extra={"X-Session-Token": session},
            )
        except GrcHttpError as error:
            # The headless API answers 401 once the session has ended and 410 if it is gone.
            if error.status not in {401, 410}:
                raise

    def current_user(self) -> dict[str, Any]:
        return obj(self.get("/iam/current-user/"), "current user")

    def change_password(self, old: str, new: str) -> None:
        body = {"old_password": old, "new_password": new, "confirm_new_password": new}
        self.request("POST", "/iam/change-password/", body=body)

    def set_password(self, user_id: str, new: str) -> None:
        body = {"user": user_id, "new_password": new, "confirm_new_password": new}
        self.request("POST", "/iam/set-password/", body=body)

    def create_token(self, name: str, days: int) -> str:
        """Create a personal access token for the current user and return its secret."""
        if not 1 <= days <= 30:
            raise GrcConfigError("Token lifetime must be between 1 and 30 days")
        answer = obj(self.post("/iam/auth-tokens/", {"name": name, "expiry": days}), "token")
        if answer.get("name") != name:
            raise GrcResponseError("The created token does not carry the requested name")
        return check_secret(answer.get("token"))

    def tokens(self) -> list[dict[str, Any]]:
        """Personal access tokens of the current user: name, expiry and digest, no secret."""
        answer = self.get("/iam/auth-tokens/")
        if not isinstance(answer, list) or not all(isinstance(row, dict) for row in answer):
            raise GrcResponseError("The token list has an unexpected shape")
        return answer

    def revoke_token(self, digest: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{32,256}", digest):
            raise GrcResponseError("A token digest has an unexpected shape")
        self.delete(f"/iam/auth-tokens/{digest}/")

    # Collections and lookups

    def list_all(
        self, path: str, params: Mapping[str, str | int] | None = None
    ) -> list[dict[str, Any]]:
        """Every row of a list endpoint. Offsets are computed here; `next` links are not
        followed, so a page can never send the token to another origin."""
        query: dict[str, str | int] = {**(params or {}), "limit": PAGE_SIZE, "offset": 0}
        rows: list[dict[str, Any]] = []
        total: int | None = None
        for _ in range(MAX_PAGES):
            page = self.get(path, query)
            if isinstance(page, list) and total is None:
                return [obj(row, "row") for row in page]
            page = obj(page, "page")
            count, results = page.get("count"), page.get("results")
            if not isinstance(count, int) or not isinstance(results, list):
                raise GrcResponseError(f"GET {route(path)} answered an unexpected page shape")
            if total is None:
                total = count
            elif count != total:
                raise GrcResponseError(f"GET {route(path)} changed size while paging")
            rows.extend(obj(row, "row") for row in results)
            if len(rows) >= total or not results:
                break
            query["offset"] = len(rows)
        if len(rows) != total:
            raise GrcResponseError(f"GET {route(path)} paging did not return every row")
        return rows

    def select(
        self,
        path: str,
        params: Mapping[str, str | int],
        *,
        honors: Mapping[str, Any],
        what: str,
    ) -> list[dict[str, Any]]:
        """Rows of a filtered list. Every row must carry `honors`; otherwise the server
        ignored the filter and the lookup fails."""
        rows = self.list_all(path, params)
        if not all(matches(row, honors) for row in rows):
            raise GrcLookupError(f"{what}: the API returned objects outside the filter")
        return rows

    def find(
        self,
        path: str,
        params: Mapping[str, str | int],
        *,
        honors: Mapping[str, Any],
        match: Mapping[str, Any],
        what: str,
    ) -> dict[str, Any] | None:
        """At most one row that carries `honors` and `match`."""
        hits = [
            row
            for row in self.select(path, params, honors=honors, what=what)
            if matches(row, match)
        ]
        if len(hits) > 1:
            raise GrcLookupError(f"{what}: expected one match, found {len(hits)}")
        return hits[0] if hits else None

    def one(
        self,
        path: str,
        params: Mapping[str, str | int],
        *,
        honors: Mapping[str, Any],
        match: Mapping[str, Any],
        what: str,
    ) -> dict[str, Any]:
        """Exactly one row that carries `honors` and `match`."""
        hit = self.find(path, params, honors=honors, match=match, what=what)
        if hit is None:
            raise GrcLookupError(f"{what}: expected one match, found 0")
        return hit

    def stored_library(self, urn: str) -> dict[str, Any]:
        return self.one(
            "/stored-libraries/",
            {"urn": urn},
            honors={"urn": urn},
            match={"urn": urn},
            what="stored library",
        )

    def import_library(self, library_id: str) -> None:
        self.post(f"/stored-libraries/{library_id}/import/", timeout=300)

    def framework(self, urn: str) -> dict[str, Any]:
        # The frameworks endpoint has no URN filter: list all and select exactly one.
        return self.one("/frameworks/", {}, honors={}, match={"urn": urn}, what="framework")

    def requirement_node(self, urn: str) -> dict[str, Any]:
        node = self.one(
            "/requirement-nodes/",
            {"urn": urn},
            honors={"urn": urn},
            match={"urn": urn},
            what="requirement node",
        )
        if node.get("assessable") is not True:
            raise GrcLookupError("requirement node: the matching node is not assessable")
        return node

    def requirement_nodes(self, framework_id: str) -> list[dict[str, Any]]:
        return self.select(
            "/requirement-nodes/",
            {"framework": framework_id},
            honors={"framework": framework_id},
            what="requirement nodes",
        )

    def requirement_assessment(self, audit_id: str, urn: str) -> dict[str, Any]:
        """The requirement assessment of one audit for one assessable requirement URN.

        The `requirement__urn` filter works; `requirement=<urn>` is silently ignored and
        would return every row of the audit, so the URN is compared here as well."""
        wanted = {"compliance_assessment": audit_id, "requirement.urn": urn}
        row = self.one(
            "/requirement-assessments/",
            {"compliance_assessment": audit_id, "requirement__urn": urn},
            honors=wanted,
            match=wanted,
            what="requirement assessment",
        )
        requirement = row.get("requirement")
        if row.get("assessable") is not True or (
            isinstance(requirement, dict)
            and "assessable" in requirement
            and requirement["assessable"] is not True
        ):
            raise GrcLookupError("requirement assessment: the requirement is not assessable")
        return row


def obj(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GrcResponseError(f"The {what} response is not a JSON object")
    return value
