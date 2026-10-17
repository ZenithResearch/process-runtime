"""Public SDK -> actual HTTP handler -> receiver, with isolated in-memory I/O.

Maximum native fixtures are generated only by the helper's cfg(test) Rust signer.
Inert authority tests assert framing only; native tests separately verify signatures.
"""

from copy import deepcopy
import hashlib
from http.client import HTTPResponse
import io
import json
import os
from pathlib import Path
import threading
import unittest
from urllib.error import HTTPError
from unittest.mock import patch

from process_runtime.authority import (
    DenyAllVerifier,
    NativeSecSHelper,
    ReceiverPolicy,
    PermissionRule,
    SecSExecutionAuthorityVerifier,
    VerifierKey,
    operation_name,
    resource_for,
)
from process_runtime.contracts import validate
from process_runtime.domain import DomainError, Snapshot
from process_runtime.http_api import make_server, parse_json
from process_runtime_client import RuntimeClient, RuntimeClientError

R = 2_097_152
P = R + 16_384 + 69
C = 65_536
A = 4_400_000
HTTP_MAX = 6 * R + 4 * ((A + 2) // 3) + 66
PATTERNS = (
    ("ascii", "a"),
    ("DEL", "\x7f"),
    ("BMP", "é"),
    ("supplementary", "🌸"),
    ("quote", '"'),
    ("backslash", "\\"),
    ("linefeed", "\n"),
    ("NUL", "\0"),
    ("mixed", 'a\x7fé🌸"\\\n\0'),
)


def command(filler):
    return {
        "schema": "runtime.command.v1",
        "operation": "run.create",
        "request_id": "budget",
        "resource": "runs/run-1",
        "expected_version": None,
        "payload": {
            "run_id": "run-1",
            "pin": {
                "process_id": "process",
                "process_version": "version",
                "compilation_hash": "0" * 64,
            },
            "inputs": {"value": filler},
        },
    }


def maximum(pattern, make=command, size=R):
    base = len(Snapshot.of(make("")).text.encode())
    unit = len(Snapshot.of(make(pattern)).text.encode()) - base
    count, tail = divmod(size - base, unit)
    value = make(pattern * count + "a" * tail)
    assert len(Snapshot.of(value).text.encode()) == size
    return value


def small_draft():
    return {
        "schema": "process.draft.v1",
        "process_id": "budget-process",
        "inputs": {"value": {"kind": "string"}},
        "steps": [
            {
                "step_id": "retain",
                "depends_on": [],
                "capabilities": [],
                "resources": [],
                "inputs": {},
                "bindings": {},
                "outputs": {},
                "max_attempts": 1,
            }
        ],
    }


def handoff(filler):
    from process_runtime.compiler import compile_draft
    from process_runtime_client import command_envelope

    return command_envelope(
        "handoff.consume",
        request_id="native-budget-handoff",
        expected_version=None,
        payload={
            "schema": "service.runtime-handoff.v1",
            "event_id": "budget-event",
            "source": "budget-source",
            "request_id": "service-request",
            "case_id": None,
            "plan_revision_id": None,
            "pin": {
                "process_id": "budget-process",
                "process_version": "budget-version",
                "compilation_hash": compile_draft(small_draft()).compilation_hash,
            },
            "inputs": {"value": filler},
            "idempotency_key": "budget-handoff",
        },
    )


class MemorySocket:
    def __init__(self, body):
        self.reader = io.BytesIO(body)
        self.sent = bytearray()
        self.timeouts = []

    def makefile(self, *args):
        return self.reader

    def sendall(self, data):
        self.sent.extend(data)

    def settimeout(self, timeout):
        self.timeouts.append(timeout)


class MemoryHTTP:
    """Run the real BaseHTTPRequestHandler without socket traffic or a database."""

    def __init__(self, server):
        self.server = server
        self.lengths = []

    def raw(self, body, headers=None):
        headers = headers or {
            "Content-Length": str(len(body)),
            "Content-Type": "application/json",
        }
        raw = (
            b"POST /v1/commands HTTP/1.0\r\n"
            + b"".join(f"{k}: {v}\r\n".encode() for k, v in headers.items())
            + b"\r\n"
            + body
        )
        connection = MemorySocket(raw)
        self.last_connection = connection
        self.server.RequestHandlerClass(connection, ("127.0.0.1", 1), self.server)
        response = HTTPResponse(MemorySocket(bytes(connection.sent)))
        response.begin()
        return response

    def open(self, call, timeout):
        self.lengths.append(len(call.data))
        response = self.raw(call.data)
        if response.status >= 400:
            raise HTTPError(
                call.full_url,
                response.status,
                response.reason,
                response.headers,
                response,
            )
        return response


class CheckingReceiver:
    def __init__(self, verifier=None):
        self.verifier = verifier
        self.calls = []

    def execute(self, body, authority):
        retained = validate(body, "command")
        if self.verifier:
            self.verifier.verify(envelope=authority, command=retained, now_ms=1001000)
        self.calls.append(
            (retained.digest, len(retained.text.encode()), len(authority))
        )
        return {
            "schema": "runtime.result.v1",
            "request_id": body["request_id"],
            "operation": body["operation"],
            "resource": body["resource"],
            "duplicate": False,
            "version": 1,
            "result": {"request_digest": retained.digest},
        }


class TransportBudgetTests(unittest.TestCase):
    def setup_client(self, receiver=None):
        receiver = receiver or CheckingReceiver()
        server = make_server(receiver)
        self.addCleanup(server.server_close)
        wire = MemoryHTTP(server)
        client = RuntimeClient("http://127.0.0.1:1")
        client.opener = wire
        return receiver, wire, client

    def test_derived_http_budget(self):
        from process_runtime.http_api import MAX_TRANSPORT_BYTES

        self.assertEqual(MAX_TRANSPORT_BYTES, HTTP_MAX)
        self.assertEqual(HTTP_MAX, 18_449_646)

    def test_exact_public_request_bound_and_adjacent_rejection(self):
        for name, pattern in PATTERNS:
            with self.subTest(name=name):
                body = maximum(pattern)
                self.assertEqual(len(validate(body, "command").text.encode()), R)
                body["payload"]["inputs"]["value"] += "a"
                with self.assertRaises(DomainError):
                    validate(body, "command")

    def test_other_envelope_and_compiler_response_limits_unchanged(self):
        from process_runtime.compiler import MAX_DOCUMENT_BYTES
        from process_runtime_client.client import MAX_RESPONSE_BYTES

        self.assertEqual(MAX_DOCUMENT_BYTES, 1_048_576)
        self.assertEqual(MAX_RESPONSE_BYTES, 4_500_000)
        for kind in (
            "result",
            "query_result",
            "event",
            "receipt",
            "artifact",
            "process_draft",
        ):
            with (
                self.subTest(kind=kind),
                self.assertRaisesRegex(DomainError, "public byte limit"),
            ):
                validate({"padding": "a" * 1_048_576}, kind)

    def test_maximum_sdk_escaping_and_full_native_envelope_placeholders(self):
        receiver, wire, client = self.setup_client()
        inert = Snapshot.of(
            {
                "schema": "runtime.secs-envelope.v1",
                "packet_hex": "00" * P,
                "signed_context_hex": "00" * C,
            }
        ).text.encode()
        self.assertEqual(len(inert), 4_358_359)
        for name, pattern in PATTERNS:
            with self.subTest(name=name):
                body = maximum(pattern)
                answer = client.execute(body, inert)
                self.assertEqual(
                    answer["result"]["request_digest"], Snapshot.of(body).digest
                )
                self.assertLessEqual(wire.lengths[-1], HTTP_MAX)
                self.assertEqual(receiver.calls[-1][1:], (R, len(inert)))
        self.assertEqual(len(receiver.calls), 9)
        self.assertEqual(max(wire.lengths), 18_392_516)

    def test_http_exact_frame_cap_and_overflow_without_body_read(self):
        receiver, wire, client = self.setup_client()
        raw = json.dumps(
            {
                "schema": "runtime.transport.v1",
                "request": command("small"),
                "authority_base64": "",
            },
            separators=(",", ":"),
        ).encode()
        raw += b" " * (HTTP_MAX - len(raw))
        self.assertEqual(wire.raw(raw).status, 200)
        self.assertEqual(
            wire.raw(
                b"",
                {
                    "Content-Length": str(HTTP_MAX + 1),
                    "Content-Type": "application/json",
                },
            ).status,
            400,
        )
        with self.assertRaises(DomainError):
            parse_json(raw + b" ")
        self.assertEqual(len(receiver.calls), 1)

    def test_inner_authority_overlimit_and_malformed_outer_frames_deny(self):
        receiver, wire, client = self.setup_client()
        with self.assertRaises(RuntimeClientError) as caught:
            client.execute(command("small"), b"x" * (A + 1))
        self.assertEqual(caught.exception.code, "unauthenticated")
        for raw in (
            b'{"schema":1,"schema":2}',
            b'{"number":NaN}',
            b'{"schema":"runtime.transport.v1","request":{},"authority_base64":"***"}',
            b'{"schema":"runtime.transport.v1","request":{},"authority_base64":"","extra":1}',
        ):
            with self.subTest(raw=raw):
                self.assertGreaterEqual(wire.raw(raw).status, 400)
        self.assertEqual(receiver.calls, [])

    def test_default_deny_unchanged_for_small_and_maximum_requests(self):
        receiver, wire, client = self.setup_client(CheckingReceiver(DenyAllVerifier()))
        for body in (command("small"), maximum("\x7f")):
            with self.assertRaises(RuntimeClientError) as caught:
                client.execute(body, b"")
            self.assertEqual(caught.exception.code, "unauthenticated")
        self.assertEqual(receiver.calls, [])

    def test_response_timeout_is_reset_after_near_deadline_body_read(self):
        receiver, wire, client = self.setup_client()
        with patch(
            "process_runtime.http_api.time.monotonic", side_effect=[100, 104.99, 104.99]
        ):
            self.assertEqual(client.execute(command("small"), b"")["version"], 1)
        self.assertAlmostEqual(wire.last_connection.timeouts[0], 0.01)
        self.assertEqual(wire.last_connection.timeouts[-1], 5)
        self.assertEqual(len(receiver.calls), 1)

    def test_final_complete_chunk_at_or_after_deadline_denies_and_releases(self):
        receiver, wire, client = self.setup_client()
        for completed_at in (105, 106):
            with self.subTest(completed_at=completed_at):
                with patch(
                    "process_runtime.http_api.time.monotonic",
                    side_effect=[100, 100, completed_at],
                ):
                    with self.assertRaises(RuntimeClientError) as caught:
                        client.execute(command("small"), b"")
                self.assertEqual(caught.exception.code, "storage_unavailable")
                self.assertEqual(receiver.calls, [])
        self.assertEqual(client.execute(command("small"), b"")["version"], 1)

    def test_body_admission_is_bounded_and_released(self):
        from process_runtime.http_api import MAX_INFLIGHT_REQUESTS

        receiver, wire, client = self.setup_client()
        arrived = threading.Barrier(MAX_INFLIGHT_REQUESTS + 1)
        release = threading.Event()
        original = receiver.execute

        def blocked(*args):
            arrived.wait(5)
            release.wait(5)
            return original(*args)

        receiver.execute = blocked
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(MAX_INFLIGHT_REQUESTS) as pool:
            pending = [
                pool.submit(client.execute, command("small"), b"")
                for _ in range(MAX_INFLIGHT_REQUESTS)
            ]
            arrived.wait(5)
            try:
                with self.assertRaises(RuntimeClientError) as caught:
                    client.execute(command("small"), b"")
                self.assertEqual(caught.exception.code, "storage_unavailable")
            finally:
                release.set()
            for result in pending:
                self.assertEqual(result.result(5)["version"], 1)
        receiver.execute = original
        self.assertEqual(client.execute(command("small"), b"")["version"], 1)

    def test_absolute_body_deadline_is_not_reset_by_progress(self):
        receiver, wire, client = self.setup_client()
        with patch("process_runtime.http_api.time.monotonic", side_effect=[0, 0, 6]):
            with self.assertRaises(RuntimeClientError):
                client.execute(command("x" * 100000), b"")
        self.assertEqual(receiver.calls, [])

    def test_admission_releases_after_malformed_timeout_and_handler_failure(self):
        receiver, wire, client = self.setup_client()
        original = receiver.execute

        def failure(*args):
            raise RuntimeError("injected handler failure")

        for _ in range(4):
            self.assertEqual(wire.raw(b"{").status, 400)
            self.assertEqual(
                wire.raw(
                    b"", {"Content-Length": "1", "Content-Type": "application/json"}
                ).status,
                400,
            )
            with patch("process_runtime.http_api.time.monotonic", side_effect=[0, 6]):
                with self.assertRaises(RuntimeClientError) as caught:
                    client.execute(command("small"), b"")
                self.assertEqual(caught.exception.code, "storage_unavailable")
            receiver.execute = failure
            with self.assertRaises(RuntimeClientError) as caught:
                client.execute(command("small"), b"")
            self.assertEqual(caught.exception.code, "storage_unavailable")
            receiver.execute = original
            self.assertEqual(client.execute(command("small"), b"")["version"], 1)

    def test_real_socket_slow_progress_does_not_extend_body_deadline(self):
        import socket, time

        receiver, wire, client = self.setup_client()
        server = wire.server
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        with patch("process_runtime.http_api.BODY_READ_SECONDS", 0.08):
            worker.start()
            try:
                with socket.create_connection(server.server_address, timeout=2) as peer:
                    peer.sendall(
                        b"POST /v1/commands HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n"
                    )
                    for _ in range(6):
                        try:
                            peer.sendall(b" ")
                        except OSError:
                            break
                        time.sleep(0.02)
                    response = HTTPResponse(peer)
                    response.begin()
                    self.assertEqual(response.status, 503)
                    self.assertEqual(
                        json.loads(response.read())["code"], "storage_unavailable"
                    )
            finally:
                server.shutdown()
                worker.join(2)
        self.assertEqual(receiver.calls, [])
        self.assertEqual(client.execute(command("small"), b"")["version"], 1)


@unittest.skipUnless(
    os.environ.get("PROCESS_RUNTIME_TRANSPORT_FIXTURES")
    and os.environ.get("PROCESS_RUNTIME_NATIVE_VERIFIER"),
    "Explicit candidate native helper/fixtures required",
)
class NativeTransportBudgetTests(unittest.TestCase):
    setup_client = TransportBudgetTests.setup_client

    @classmethod
    def setUpClass(cls):
        cls.cases = json.loads(
            Path(os.environ["PROCESS_RUNTIME_TRANSPORT_FIXTURES"]).read_text()
        )["fixtures"]
        binary = Path(os.environ["PROCESS_RUNTIME_NATIVE_VERIFIER"])
        cls.helper = NativeSecSHelper(
            binary, hashlib.sha256(binary.read_bytes()).hexdigest()
        )

    def test_full_native_signature_receiver_via_sdk_and_http(self):
        for fixture in self.cases:
            with self.subTest(case=fixture["name"]):
                snapshot = Snapshot(fixture["request"])
                policy = ReceiverPolicy(
                    "runtime://receiver-local",
                    (
                        VerifierKey(
                            "synthetic-verifier",
                            fixture["public_key_hex"],
                            not_before=999,
                            not_after=1200,
                        ),
                    ),
                    ((operation_name(snapshot), "a" * 64, "runtime-v1"),),
                    (
                        PermissionRule(
                            "synthetic-subject",
                            operation_name(snapshot),
                            resource_for(snapshot),
                            "allow",
                            999000,
                            1200000,
                        ),
                    ),
                )
                verifier = SecSExecutionAuthorityVerifier(self.helper, lambda: policy)
                receiver, wire, client = self.setup_client(CheckingReceiver(verifier))
                authority = Snapshot.of(fixture["envelope"]).text.encode()
                self.assertEqual(
                    len(bytes.fromhex(fixture["envelope"]["packet_hex"])),
                    len(snapshot.text.encode()) + 16_384 + 69,
                )
                self.assertEqual(
                    len(bytes.fromhex(fixture["envelope"]["signed_context_hex"])), C
                )
                response = client.execute(snapshot.value, authority)
                self.assertEqual(response["result"]["request_digest"], snapshot.digest)
                self.assertLessEqual(wire.lengths[0], HTTP_MAX)
                for field in ("packet_hex", "signed_context_hex"):
                    changed = deepcopy(fixture["envelope"])
                    changed[field] += "00"
                    with self.assertRaises(RuntimeClientError):
                        client.execute(
                            snapshot.value, Snapshot.of(changed).text.encode()
                        )

    def test_maximum_native_handoff_mutates_isolated_runtime_and_exact_retry_once(self):
        from process_runtime.application import Runtime
        from process_runtime.authority import LocalDevUntrustedVerifier
        from process_runtime.sqlite_store import SQLiteStore
        from process_runtime.ports import RecordKind
        from process_runtime_client import command_envelope
        import tempfile

        case = next(item for item in self.cases if item["name"] == "handoff-input-max")
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStore(Path(directory) / "runtime.db")
            self.addCleanup(store.close)
            runtime = Runtime(
                store,
                verifier=LocalDevUntrustedVerifier("test-setup"),
                environment="test",
                allow_local_dev_untrusted=True,
                clock=lambda: 1001000,
            )
            _, wire, client = self.setup_client(runtime)
            # Explicit test-only local setup, then actual native authority for the full request.
            from process_runtime.authority import local_dev_envelope

            def setup(body):
                import uuid

                evidence = local_dev_envelope(
                    Snapshot.of(body),
                    now_ms=1001000,
                    session_id="1" * 32,
                    nonce=uuid.uuid4().hex[:24],
                )
                return client.execute(body, evidence)

            draft = small_draft()
            setup(
                command_envelope(
                    "process.draft.put",
                    request_id="budget-draft",
                    expected_version=None,
                    payload={
                        "draft": draft,
                        "provenance": {
                            "source_id": "budget-fixture",
                            "media_type": "application/json",
                            "content_hash": Snapshot.of(draft).digest,
                            "parser": "explicit-json-v1",
                            "uncertainties": [],
                        },
                    },
                )
            )
            setup(
                command_envelope(
                    "process.publish",
                    request_id="budget-publish",
                    expected_version=1,
                    payload={
                        "process_id": "budget-process",
                        "draft_revision": 1,
                        "version_id": "budget-version",
                    },
                )
            )
            snapshot = Snapshot(case["request"])
            policy = ReceiverPolicy(
                "runtime://receiver-local",
                (
                    VerifierKey(
                        "synthetic-verifier",
                        case["public_key_hex"],
                        not_before=999,
                        not_after=1200,
                    ),
                ),
                ((operation_name(snapshot), "a" * 64, "runtime-v1"),),
                (
                    PermissionRule(
                        "synthetic-subject",
                        operation_name(snapshot),
                        resource_for(snapshot),
                        "allow",
                        999000,
                        1200000,
                    ),
                ),
            )
            runtime.verifier = SecSExecutionAuthorityVerifier(
                self.helper, lambda: policy
            )
            runtime.allow_local_dev = False
            evidence = Snapshot.of(case["envelope"]).text.encode()
            before = store.event_high_watermark()
            # Full transport acceptance does not waive the independent 1MiB input cap.
            too_large = next(item for item in self.cases if item["name"] == "handoff")
            with self.assertRaises(RuntimeClientError) as rejected:
                client.execute(
                    Snapshot(too_large["request"]).value,
                    Snapshot.of(too_large["envelope"]).text.encode(),
                )
            self.assertEqual(rejected.exception.code, "malformed_request")
            self.assertEqual(store.event_high_watermark(), before)
            self.assertGreater(len(snapshot.text.encode()), 1_048_576)
            self.assertEqual(
                len(Snapshot.of(snapshot.value["payload"]["inputs"]).text.encode()),
                1_048_576,
            )
            response = client.execute(snapshot.value, evidence)
            self.assertFalse(response["duplicate"])
            self.assertLess(len(Snapshot.of(response).text.encode()), 1_048_576)
            record = store.get(RecordKind.PROCESS_RUN, response["result"]["run_id"])
            self.assertEqual(
                record.value.value["inputs"], snapshot.value["payload"]["inputs"]
            )
            self.assertTrue(client.execute(snapshot.value, evidence)["duplicate"])
            self.assertEqual(store.event_high_watermark(), before + 1)
            store.close()

    def test_native_stdio_and_metadata_bounds_deny(self):
        import subprocess

        rejected = subprocess.run(
            [str(self.helper.executable)],
            input=b" " * (9 * 1024 * 1024 + 1),
            capture_output=True,
            timeout=5,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(rejected.stdout, b"")
        self.assertEqual(rejected.stderr, b'{"error":"native_authority_rejected"}\n')
        with patch("process_runtime.authority.subprocess.run") as launch:
            with self.assertRaises(DomainError):
                self.helper.verify({"schema": "x", "audience": "x" * 65_536})
            launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
