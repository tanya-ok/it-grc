"""Offline tests for the CISO Assistant client. Servers run on loopback HTTPS only and
answer with recorded synthetic responses; no external network is used."""

from __future__ import annotations

import os
import shutil
import ssl
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from grc_fake import (
    FRAMEWORK_URN,
    NODE_PREFIX,
    OPENSSL,
    RESET,
    Certificates,
    Reply,
    Script,
    TlsServer,
    make_certificates,
)

from it_grc import grc_client as gc

AUDIT = "6f7c1d2e-0a3b-4c5d-8e9f-0123456789ab"
OTHER_AUDIT = "11111111-2222-4333-8444-555555555555"
URN = NODE_PREFIX + "node236"
SECRET = "S3cr3t-" + "Z" * 40
MARKER = "BODY-MARKER-7f3a"


def node(urn: str = URN, *, assessable: bool = True, **extra: Any) -> dict[str, Any]:
    return {
        "id": "3b1f8c2a-9d4e-4f5a-8b6c-7d8e9f0a1b2c",
        "urn": urn,
        "ref_id": None,
        "name": "5. Implement the Audit/System Activity Review Process",
        "assessable": assessable,
        **extra,
    }


def assessment(urn: str = URN, *, audit: str = AUDIT, assessable: bool = True) -> dict[str, Any]:
    return {
        "id": "9a8b7c6d-5e4f-4a3b-9c2d-1e0f9a8b7c6d",
        "assessable": assessable,
        "compliance_assessment": {"id": audit, "str": "HIPAA Security Rule lab evidence"},
        "requirement": {"id": "3b1f8c2a-9d4e-4f5a-8b6c-7d8e9f0a1b2c", "urn": urn},
        "result": "not_assessed",
        "status": "to_do",
    }


def listing(*rows: dict[str, Any]) -> Reply:
    return Reply(200, {"count": len(rows), "next": None, "previous": None, "results": list(rows)})


class OriginAndRouteTests(unittest.TestCase):
    def test_only_https_origins_without_paths_are_accepted(self) -> None:
        for origin in (
            "http://localhost:18443",
            "https://localhost",
            "https://localhost:18443/api",
            "https://localhost:0",
            "file:///etc/passwd",
            "https://user@localhost:18443",
        ):
            with self.subTest(origin=origin), self.assertRaises(gc.GrcConfigError):
                gc.check_origin(origin)
        self.assertEqual(gc.check_origin("https://localhost:18443"), "https://localhost:18443")

    def test_routes_in_messages_hide_ids_urns_digests_and_queries(self) -> None:
        self.assertEqual(gc.route("/iam/auth-tokens/" + "ab" * 64 + "/"), "/iam/auth-tokens/{id}/")
        self.assertEqual(
            gc.route(f"/stored-libraries/{URN}/import/"), "/stored-libraries/{id}/import/"
        )
        self.assertEqual(gc.route("/users/?email=bridge@example.org"), "/users/")
        error = gc.http_error("DELETE", "/iam/auth-tokens/" + "cd" * 64 + "/", 404)
        self.assertIsInstance(error, gc.GrcNotFoundError)
        self.assertEqual(str(error), "DELETE /iam/auth-tokens/{id}/ answered HTTP 404")


class TlsContextTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)

    def test_missing_or_invalid_ca_files_are_refused(self) -> None:
        garbage = self.folder / "garbage.pem"
        garbage.write_text("not a certificate\n")
        empty = self.folder / "empty.pem"
        empty.write_text("")
        for path in (self.folder / "missing.pem", self.folder, garbage, empty):
            with self.subTest(path=path.name), self.assertRaises(gc.GrcConfigError):
                gc.tls_context(path)
        with self.assertRaises(gc.GrcConfigError):
            gc.GrcClient("https://localhost:18443", self.folder / "missing.pem")

    @unittest.skipUnless(OPENSSL, "openssl is required to create a test CA")
    def test_context_trusts_only_the_ca_file_and_verifies_host_names(self) -> None:
        certificates = make_certificates(self.folder / "ca")
        context = gc.tls_context(certificates.ca)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(len(context.get_ca_certs()), 1)


@unittest.skipUnless(OPENSSL, "openssl is required to create a test CA")
class ServerTestCase(unittest.TestCase):
    certificates: Certificates
    other: Certificates

    @classmethod
    def setUpClass(cls) -> None:
        cls.folder = Path(tempfile.mkdtemp())
        cls.certificates = make_certificates(cls.folder / "trusted")
        cls.other = make_certificates(cls.folder / "other")

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.folder)

    def setUp(self) -> None:
        self.script = Script()
        self.server = TlsServer(self.script, self.certificates)
        self.addCleanup(self.server.stop)
        self.sleeps: list[float] = []

    def client(self, **options: Any) -> gc.GrcClient:
        settings = gc.ClientOptions(sleep=self.sleeps.append, **options)
        return gc.GrcClient(self.server.origin(), self.certificates.ca, options=settings)


class TransportTests(ServerTestCase):
    def test_json_request_carries_the_token_only_in_the_header(self) -> None:
        self.script.on("GET", "/api/iam/current-user/", Reply(200, {"email": "bridge@example.org"}))
        client = self.client().with_token(SECRET)
        self.assertEqual(client.current_user(), {"email": "bridge@example.org"})
        hit = self.script.hits[0]
        self.assertEqual(hit.headers["authorization"], "Token " + SECRET)
        self.assertEqual(hit.headers["accept"], "application/json")
        self.assertNotIn(SECRET, hit.path + str(hit.query))
        self.assertNotIn(SECRET, repr(client))

    def test_redirects_are_never_followed(self) -> None:
        for location in ("/api/target/", "https://attacker.example/api/target/"):
            self.script.on("GET", "/api/folders/", Reply(302, None, headers={"Location": location}))
            self.script.on("GET", "/api/target/", Reply(200, {"followed": True}))
            with self.subTest(location=location), self.assertRaises(gc.GrcRedirectError):
                self.client().with_token(SECRET).get("/folders/")
            self.assertEqual(self.script.count("GET", "/api/target/"), 0)

    def test_proxy_environment_is_ignored(self) -> None:
        self.script.on("GET", "/api/build/", Reply(200, {"version": "v4.1.1"}))
        proxies = dict.fromkeys(
            ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"), "http://127.0.0.1:9"
        )
        with patch.dict(os.environ, proxies):
            self.assertEqual(self.client().get("/build/"), {"version": "v4.1.1"})
        self.assertEqual(self.script.count("GET", "/api/build/"), 1)

    def test_host_name_and_ca_are_verified(self) -> None:
        self.script.on("GET", "/api/build/", Reply(200, {}))
        by_address = gc.GrcClient(self.server.origin("127.0.0.1"), self.certificates.ca)
        untrusted = gc.GrcClient(self.server.origin(), self.other.ca)
        for client in (by_address, untrusted):
            with self.subTest(client=client), self.assertRaises(gc.GrcTransportError) as raised:
                client.get("/build/")
            self.assertIn("TLS verification failed", str(raised.exception))
        self.assertEqual(self.script.hits, [])

    def test_error_messages_contain_no_body_and_no_secret(self) -> None:
        body = {"detail": f"{MARKER} {SECRET}", "password": [SECRET]}
        self.script.on("POST", "/api/iam/change-password/", Reply(400, body))
        self.script.on("GET", "/api/folders/", Reply(500, body))
        client = self.client(retry_delays=()).with_token(SECRET)
        calls = [
            lambda: client.change_password(SECRET, SECRET + "x"),
            lambda: client.get("/folders/"),
        ]
        for call in calls:
            with self.assertRaises(gc.GrcHttpError) as raised:
                call()
            error = raised.exception
            for text in (str(error), repr(error), str(error.args)):
                self.assertNotIn(MARKER, text)
                self.assertNotIn(SECRET, text)
            self.assertTrue(error.__suppress_context__)

    def test_multipart_upload_is_sent_once_and_carries_the_file(self) -> None:
        content = b'{"kind":"extract"}\n'
        self.script.on("POST", "/api/evidence-revisions/", Reply(500, {}), Reply(201, {"id": 1}))
        client = self.client().with_token(SECRET)
        with self.assertRaises(gc.GrcHttpError):
            client.post_form(
                "/evidence-revisions/",
                {"evidence": AUDIT},
                file_field="attachment",
                file_name="itgrc-ev-access.json",
                content=content,
            )
        self.assertEqual(self.script.count("POST", "/api/evidence-revisions/"), 1)
        hit = self.script.hits[-1]
        self.assertTrue(hit.headers["content-type"].startswith("multipart/form-data; boundary="))
        self.assertIn(content, hit.raw)
        self.assertIn(b'filename="itgrc-ev-access.json"', hit.raw)
        for name in ("../etc/passwd", "a b.json", ""):
            with self.subTest(name=name), self.assertRaises(gc.GrcConfigError):
                client.post_form(
                    "/evidence-revisions/", {}, file_field="attachment", file_name=name, content=b""
                )
        self.assertEqual(self.script.count("POST", "/api/evidence-revisions/"), 1)

    def test_failed_login_raises_a_fixed_authentication_error(self) -> None:
        self.script.on(
            "POST",
            "/api/_allauth/app/v1/auth/login",
            Reply(400, {"errors": [{"message": MARKER}]}),
        )
        with self.assertRaises(gc.GrcAuthError) as raised:
            self.client().login("admin@example.org", SECRET)
        self.assertEqual(raised.exception.status, 400)
        self.assertNotIn(MARKER, str(raised.exception))
        self.assertNotIn(SECRET, str(raised.exception))

    def test_responses_are_bounded_and_json_only(self) -> None:
        self.script.on("GET", "/api/big/", Reply(200, {"blob": "x" * 4096}))
        self.script.on(
            "GET", "/api/html/", Reply(200, raw=b"<html></html>", content_type="text/html")
        )
        self.script.on("GET", "/api/broken/", Reply(200, raw=b"{not json"))
        client = self.client(max_bytes=1024)
        for path in ("/big/", "/html/", "/broken/"):
            with self.subTest(path=path), self.assertRaises(gc.GrcResponseError):
                client.get(path)

    def test_get_retries_with_backoff_on_5xx(self) -> None:
        self.script.on(
            "GET", "/api/build/", Reply(503, {}), Reply(502, {}), Reply(200, {"version": "v4.1.1"})
        )
        self.assertEqual(self.client().get("/build/"), {"version": "v4.1.1"})
        self.assertEqual(self.script.count("GET", "/api/build/"), 3)
        self.assertEqual(self.sleeps, [0.5, 1.0])

    def test_get_retries_after_a_connection_reset(self) -> None:
        self.script.on("GET", "/api/build/", RESET, Reply(200, {"version": "v4.1.1"}))
        self.assertEqual(self.client().get("/build/"), {"version": "v4.1.1"})
        self.assertEqual(self.script.count("GET", "/api/build/"), 2)
        self.assertEqual(self.sleeps, [0.5])

    def test_no_retry_for_post_patch_or_client_errors(self) -> None:
        self.script.on("POST", "/api/folders/", Reply(503, {}))
        self.script.on("PATCH", "/api/users/x/", Reply(502, {}))
        self.script.on("GET", "/api/users/", Reply(404, {}))
        self.script.on("GET", "/api/perimeters/", Reply(400, {}))
        client = self.client()
        with self.assertRaises(gc.GrcHttpError):
            client.post("/folders/", {"name": "probe"})
        with self.assertRaises(gc.GrcHttpError):
            client.patch("/users/x/", {"user_groups": []})
        with self.assertRaises(gc.GrcNotFoundError):
            client.get("/users/")
        with self.assertRaises(gc.GrcHttpError):
            client.get("/perimeters/")
        self.assertEqual(len(self.script.hits), 4)
        self.assertEqual(self.sleeps, [])

    def test_retries_stop_after_the_last_delay(self) -> None:
        self.script.on("GET", "/api/build/", Reply(503, {}))
        with self.assertRaises(gc.GrcHttpError) as raised:
            self.client().get("/build/")
        self.assertEqual(raised.exception.status, 503)
        self.assertEqual(self.script.count("GET", "/api/build/"), 4)

    def test_a_reset_during_post_is_not_retried(self) -> None:
        self.script.on("POST", "/api/folders/", RESET)
        with self.assertRaises(gc.GrcTransportError):
            self.client().post("/folders/", {"name": "probe"})
        self.assertEqual(self.script.count("POST", "/api/folders/"), 1)


class PaginationTests(ServerTestCase):
    def rows(self, count: int) -> list[dict[str, Any]]:
        return [node(f"{NODE_PREFIX}node{index}") for index in range(count)]

    def test_offsets_are_computed_locally_and_next_links_are_ignored(self) -> None:
        rows = self.rows(250)

        def answer(offset: int) -> Reply:
            evil = "https://attacker.example/api/requirement-nodes/?offset=999"
            return Reply(
                200,
                {
                    "count": 250,
                    "next": evil,
                    "previous": None,
                    "results": rows[offset : offset + 100],
                },
            )

        self.script.on("GET", "/api/requirement-nodes/", answer(0), answer(100), answer(200))
        got = self.client().list_all("/requirement-nodes/", {"framework": "f"})
        self.assertEqual([row["urn"] for row in got], [row["urn"] for row in rows])
        offsets = [hit.query["offset"] for hit in self.script.hits]
        self.assertEqual(offsets, ["0", "100", "200"])
        self.assertTrue(all(hit.query["framework"] == "f" for hit in self.script.hits))

    def test_inconsistent_pages_are_refused(self) -> None:
        rows = self.rows(150)
        first = Reply(200, {"count": 150, "next": None, "results": rows[:100]})
        shrunk = Reply(200, {"count": 120, "next": None, "results": rows[100:120]})
        empty = Reply(200, {"count": 150, "next": None, "results": []})
        for second in (shrunk, empty):
            self.script.on("GET", "/api/requirement-nodes/", first, second)
            with (
                self.subTest(second=second.payload["count"]),
                self.assertRaises(gc.GrcResponseError),
            ):
                self.client().list_all("/requirement-nodes/")


class LookupTests(ServerTestCase):
    def lookup_node(self, *replies: Reply) -> dict[str, Any]:
        self.script.on("GET", "/api/requirement-nodes/", *replies)
        return self.client().with_token(SECRET).requirement_node(URN)

    def test_single_assessable_node_with_the_exact_urn_is_returned(self) -> None:
        self.assertEqual(self.lookup_node(listing(node()))["urn"], URN)
        self.assertEqual(self.script.hits[0].query["urn"], URN)

    def test_node_lookup_failures(self) -> None:
        cases = {
            "zero results": listing(),
            "two results": listing(node(), node()),
            "not assessable": listing(node(assessable=False)),
            "assessable missing": listing({**node(), "assessable": None}),
            # The filter was ignored and the API returned another node.
            "urn mismatch": listing(node(NODE_PREFIX + "node235")),
            "prefix only": listing(node(URN + "0")),
        }
        for name, reply in cases.items():
            with self.subTest(case=name), self.assertRaises(gc.GrcLookupError):
                self.lookup_node(reply)

    def lookup_assessment(self, *replies: Reply) -> dict[str, Any]:
        self.script.on("GET", "/api/requirement-assessments/", *replies)
        return self.client().with_token(SECRET).requirement_assessment(AUDIT, URN)

    def test_requirement_assessment_lookup_uses_requirement_urn_filter(self) -> None:
        row = self.lookup_assessment(listing(assessment()))
        self.assertEqual(row["requirement"]["urn"], URN)
        query = self.script.hits[0].query
        self.assertEqual(query["requirement__urn"], URN)
        self.assertEqual(query["compliance_assessment"], AUDIT)
        self.assertNotIn("requirement", query)

    def test_requirement_assessment_lookup_failures(self) -> None:
        # In the spike an ignored filter returned all 179 rows of the audit.
        ignored = [assessment(f"{NODE_PREFIX}node{i}", assessable=i >= 27) for i in range(179)]
        cases = {
            "zero results": listing(),
            "two results": listing(assessment(), assessment()),
            "filter ignored": listing(*ignored),
            "not assessable": listing(assessment(assessable=False)),
            "urn mismatch": listing(assessment(NODE_PREFIX + "node1")),
            "other audit": listing(assessment(audit=OTHER_AUDIT)),
            "requirement not nested": listing({**assessment(), "requirement": "3b1f8c2a"}),
            "nested requirement not assessable": listing(
                {**assessment(), "requirement": {"id": "r", "urn": URN, "assessable": False}}
            ),
        }
        for name, reply in cases.items():
            with self.subTest(case=name), self.assertRaises(gc.GrcLookupError):
                self.lookup_assessment(reply)

    def test_framework_is_selected_by_exact_urn(self) -> None:
        other = {"id": "a", "urn": "urn:intuitem:risk:framework:nist-csf-2.0"}
        wanted = {"id": "b", "urn": FRAMEWORK_URN}
        self.script.on("GET", "/api/frameworks/", listing(other, wanted))
        self.assertEqual(self.client().framework(FRAMEWORK_URN)["id"], "b")
        for reply in (listing(other), listing(wanted, dict(wanted))):
            self.script.on("GET", "/api/frameworks/", reply)
            with self.assertRaises(gc.GrcLookupError):
                self.client().framework(FRAMEWORK_URN)

    def test_filtered_lookups_refuse_rows_outside_the_filter(self) -> None:
        rows = [{"id": "1", "email": "admin@example.org"}, {"id": "2", "email": "x@example.org"}]
        self.script.on("GET", "/api/users/", listing(*rows))
        wanted = {"email": "bridge@example.org"}
        with self.assertRaises(gc.GrcLookupError):
            self.client().find("/users/", wanted, honors=wanted, match={}, what="bridge user")


if __name__ == "__main__":
    unittest.main()
