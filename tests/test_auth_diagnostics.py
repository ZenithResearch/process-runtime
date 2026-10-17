"""Public diagnostic metadata, unchanged decisions and in-memory HTTP boundaries."""
from dataclasses import replace
import io
import json
import logging
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from process_runtime import http_api
from process_runtime.application import _AdmissionClosed
from process_runtime.authority import (
    DEFAULT_AUDIENCE, MAX_AUTHORITY_BYTES, MAX_CONTEXT_MS, OPCODES, LocalDevUntrustedVerifier,
    authorize_binding, resource_for,
)
from process_runtime.contracts import ERROR_CODES, validate
from process_runtime.domain import DomainError, Snapshot
from process_runtime.ports import VerifiedAuthority
from process_runtime_client import RuntimeClient, RuntimeClientError
from test_transport_budget import MemoryHTTP


MARKER = "DIAGNOSTIC-POISON-DO-NOT-LOG"
WINDOW_DETAIL = "Authority is expired, future dated or exceeds lifetime"


def request_snapshot():
    return validate({"schema": "runtime.query.v1", "operation": "run.get",
                     "payload": {"run_id": "run-1"}}, "query")


def verified(request, issued=1000, expires=61000, **changes):
    value = VerifiedAuthority("subject", "holder", DEFAULT_AUDIENCE, "run.get",
        resource_for(request), request.digest, issued, expires, "01" * 16,
        OPCODES["run.get"], "02" * 12, "a" * 64, "local_dev_untrusted")
    return replace(value, **changes)


def local_envelope(**changes):
    value = {"schema": "runtime.local-dev-envelope.v1", "session_id": "01" * 16,
             "nonce": "02" * 12, "issued_at_ms": 1000, "expires_at_ms": 61000}
    value.update(changes)
    return json.dumps(value, separators=(",", ":")).encode()


def actor_command():
    return {"schema": "runtime.command.v1", "operation": "actor.register",
            "request_id": MARKER, "resource": "actors/actor-1", "expected_version": None,
            "payload": {"actor_id": "actor-1", "capabilities": [], "resources": []}}


def expected_line(reason):
    return json.dumps({"event": "runtime.auth_denied", "code": "unauthenticated",
                       "reason": reason}, separators=(",", ":"))


class DomainErrorDiagnosticCompatibilityTests(unittest.TestCase):
    def test_legacy_construction_preserves_type_dict_args_and_text(self):
        for kwargs in ({}, {"diagnostic_reason": None}):
            with self.subTest(kwargs=kwargs):
                error = DomainError("unauthenticated", MARKER, **kwargs)
                self.assertIs(type(error), DomainError)
                self.assertIsInstance(error, ValueError)
                self.assertEqual(error.__dict__, {"code": "unauthenticated"})
                self.assertEqual(error.args, (MARKER,))
                self.assertEqual(str(error), MARKER)

    def test_optional_metadata_is_keyword_only_and_not_exception_text(self):
        error = DomainError("unauthenticated", MARKER, diagnostic_reason="authority_expired")
        self.assertEqual(error.args, (MARKER,))
        self.assertEqual(str(error), MARKER)
        self.assertEqual(error.code, "unauthenticated")
        self.assertEqual(error.diagnostic_reason, "authority_expired")
        with self.assertRaises(TypeError):
            DomainError("unauthenticated", MARKER, "authority_expired")

    def test_existing_subclass_retryability_and_explicit_cause_are_preserved(self):
        cause = ValueError(MARKER)
        try:
            raise DomainError("unauthenticated", "unchanged", diagnostic_reason="authority_future") from cause
        except DomainError as error:
            self.assertIs(error.__cause__, cause)
            self.assertTrue(error.__suppress_context__)
            self.assertEqual(error.args, ("unchanged",))
        existing = _AdmissionClosed("storage_unavailable", "unchanged")
        self.assertTrue(existing.retryable)
        self.assertEqual(existing.__dict__, {"code": "storage_unavailable"})


class AuthorityDiagnosticTests(unittest.TestCase):
    def test_admitted_time_boundaries_and_maximum_lifetime_are_unchanged(self):
        request = request_snapshot()
        for issued, expires, now in ((1000, 61000, 1000), (1000, 61000, 60999),
                                     (1000, 1001, 1000)):
            with self.subTest(issued=issued, expires=expires, now=now):
                self.assertIsNone(authorize_binding(verified(request, issued, expires),
                                                   request, now, allow_local_dev=True))
        self.assertEqual(MAX_CONTEXT_MS, 60000)

    def test_denied_time_boundaries_and_overlap_priority_keep_old_error(self):
        request = request_snapshot()
        cases = ((1000, 61000, 999, "authority_future"),
                 (1000, 61000, 61000, "authority_expired"),
                 (1000, 61000, 61001, "authority_expired"),
                 (1000, 1000, 999, "authority_lifetime_invalid"),
                 (1000, 1000, 1000, "authority_lifetime_invalid"),
                 (1001, 1000, 1000, "authority_lifetime_invalid"),
                 (1000, 61001, 999, "authority_lifetime_invalid"),
                 (1000, 61001, 62000, "authority_lifetime_invalid"))
        for issued, expires, now, reason in cases:
            with self.subTest(issued=issued, expires=expires, now=now):
                with self.assertRaises(DomainError) as caught:
                    authorize_binding(verified(request, issued, expires), request, now, allow_local_dev=True)
                error = caught.exception
                self.assertEqual(error.code, "unauthenticated")
                self.assertEqual(error.args, (WINDOW_DETAIL,))
                self.assertEqual(str(error), WINDOW_DETAIL)
                self.assertEqual(error.diagnostic_reason, reason)

    def test_invalid_integer_fields_keep_malformed_authority_and_chaining(self):
        request = request_snapshot()
        for changes, now in (({"issued_at_ms": True}, 1000),
                             ({"expires_at_ms": False}, 1000), ({}, True),
                             ({"issued_at_ms": 0}, 1000)):
            with self.subTest(changes=changes, now=now), self.assertRaises(DomainError) as caught:
                authorize_binding(replace(verified(request), **changes), request, now, allow_local_dev=True)
            self.assertEqual(caught.exception.code, "unauthenticated")
            self.assertEqual(caught.exception.args, ("Malformed verified authority",))
            self.assertEqual(caught.exception.diagnostic_reason, "verified_authority_malformed")
            self.assertIsInstance(caught.exception.__cause__, DomainError)

    def test_missing_mode_and_forbidden_binding_keep_existing_codes(self):
        request = request_snapshot()
        cases = ((None, True, "unauthenticated", "verified_authority_missing"),
                 (verified(request), False, "unauthenticated", "authority_mode_not_admitted"),
                 (verified(request, resource="runs/other"), True, "forbidden", None))
        for value, allow, code, reason in cases:
            with self.subTest(code=code, reason=reason), self.assertRaises(DomainError) as caught:
                authorize_binding(value, request, 1000, allow_local_dev=allow)
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(getattr(caught.exception, "diagnostic_reason", None), reason)

    def test_malformed_duplicate_nonfinite_and_nonbytes_envelopes_keep_errors(self):
        verifier = LocalDevUntrustedVerifier("subject")
        for raw, reason in ((b'{"nonce":"a","nonce":"b"}', "authority_envelope_malformed"),
                            (b'{"issued_at_ms":NaN}', "authority_envelope_malformed"),
                            (b"[]", "authority_envelope_malformed"),
                            (bytes([255]), "authority_envelope_malformed"),
                            ("not-bytes", "authority_envelope_bounds"),
                            (b"x" * (MAX_AUTHORITY_BYTES + 1), "authority_envelope_bounds")):
            with self.subTest(raw=raw), self.assertRaises(DomainError) as caught:
                verifier.verify(envelope=raw, command=request_snapshot(), now_ms=1000)
            self.assertEqual(caught.exception.code, "unauthenticated")
            self.assertEqual(caught.exception.diagnostic_reason, reason)

    def test_local_development_envelope_shape_is_a_fixed_reason(self):
        verifier = LocalDevUntrustedVerifier("subject")
        for raw in (b"{}", local_envelope(extra=MARKER),
                    local_envelope(schema="runtime.local-dev-envelope.v9")):
            with self.subTest(raw=raw), self.assertRaises(DomainError) as caught:
                verifier.verify(envelope=raw, command=request_snapshot(), now_ms=1000)
            self.assertEqual(caught.exception.args, ("Expected explicit local development authority",))
            self.assertEqual(caught.exception.diagnostic_reason, "local_dev_envelope_shape")

    def test_valid_local_development_verification_has_no_diagnostic_state(self):
        value = LocalDevUntrustedVerifier("subject").verify(
            envelope=local_envelope(), command=request_snapshot(), now_ms=1000)
        self.assertEqual(value.mode, "local_dev_untrusted")
        self.assertEqual(value.issued_at_ms, 1000)
        self.assertEqual(value.expires_at_ms, 61000)


class AuthDiagnosticHTTPTests(unittest.TestCase):
    def make_wire(self, denial, *, allow=True, verifier=None):
        verifier = LocalDevUntrustedVerifier("subject") if verifier is None else verifier
        class Receiver:
            allow_local_dev = allow
            def execute(self, body, authority):
                if denial is not None:
                    raise denial
                return {"ok": True}
        receiver = Receiver()
        receiver.verifier = verifier
        server = http_api.make_server(receiver)
        self.addCleanup(server.server_close)
        return MemoryHTTP(server)

    def body(self, *, encoded=""):
        return json.dumps({"schema": "runtime.transport.v1", "request": actor_command(),
                           "authority_base64": encoded}, separators=(",", ":")).encode()

    def assert_error(self, response, *, retryable=False, request_id=MARKER):
        self.assertEqual(response.status, 401)
        value = json.loads(response.read())
        self.assertEqual(value, {"schema": "runtime.error.v1", "request_id": request_id,
            "code": "unauthenticated", "detail": "Runtime request was rejected: unauthenticated",
            "retryable": retryable})
        return value

    def test_annotated_denial_keeps_generic_response_and_one_fixed_line(self):
        error = DomainError("unauthenticated", MARKER, diagnostic_reason="authority_expired")
        error.__context__ = ValueError(MARKER)
        wire = self.make_wire(error)
        with patch("sys.stderr", SimpleNamespace(write=Mock(), flush=Mock())) as sink:
            value = self.assert_error(wire.raw(self.body()))
        self.assertNotIn("reason", value)
        sink.write.assert_called_once_with(expected_line("authority_expired") + "\n")
        sink.flush.assert_called_once_with()

    def test_sdk_code_retryability_and_uncertainty_are_unchanged(self):
        error = DomainError("unauthenticated", MARKER, diagnostic_reason="authority_future")
        error.retryable = True
        wire = self.make_wire(error)
        client = RuntimeClient("http://127.0.0.1:1")
        client.opener = wire
        with patch("sys.stderr", SimpleNamespace(write=Mock(), flush=Mock())) as sink, self.assertRaises(RuntimeClientError) as caught:
            client.execute(actor_command(), evidence=MARKER.encode())
        self.assertEqual(caught.exception.code, "unauthenticated")
        self.assertTrue(caught.exception.retryable)
        self.assertFalse(caught.exception.uncertain)
        sink.write.assert_called_once_with(expected_line("authority_future") + "\n")
        sink.flush.assert_called_once_with()

    def test_unknown_unhashable_and_str_subclass_metadata_use_fixed_fallback(self):
        class PoisonText(str):
            def __hash__(self):
                raise AssertionError("Subclass hashing must not occur")
            def __str__(self):
                raise AssertionError("Subclass formatting must not occur")
        values = (None, MARKER, MARKER + "\n" + "x" * 4096, [], {}, 1,
                  PoisonText("authority_expired"))
        for reason in values:
            with self.subTest(kind=type(reason).__name__):
                wire = self.make_wire(DomainError("unauthenticated", MARKER, diagnostic_reason=reason))
                with patch("sys.stderr", SimpleNamespace(write=Mock(), flush=Mock())) as sink:
                    self.assert_error(wire.raw(self.body()))
                sink.write.assert_called_once_with(expected_line("unclassified") + "\n")
                sink.flush.assert_called_once_with()

    def test_error_subclass_reason_property_and_string_are_never_evaluated(self):
        calls = []
        class PoisonError(DomainError):
            @property
            def diagnostic_reason(self):
                calls.append("reason")
                raise AssertionError(MARKER)
            def __str__(self):
                calls.append("str")
                raise AssertionError(MARKER)
        wire = self.make_wire(PoisonError("unauthenticated", MARKER))
        with patch("sys.stderr", SimpleNamespace(write=Mock(), flush=Mock())) as sink:
            self.assert_error(wire.raw(self.body()))
        self.assertEqual(calls, [])
        sink.write.assert_called_once_with(expected_line("unclassified") + "\n")
        sink.flush.assert_called_once_with()

    def test_only_explicit_true_and_exact_builtin_verifier_log(self):
        class OtherVerifier:
            pass
        class DerivedVerifier(LocalDevUntrustedVerifier):
            pass
        cases = ((False, LocalDevUntrustedVerifier("subject")),
                 (1, LocalDevUntrustedVerifier("subject")),
                 ("true", LocalDevUntrustedVerifier("subject")),
                 (True, OtherVerifier()), (True, DerivedVerifier("subject")))
        for allow, verifier in cases:
            with self.subTest(allow=allow, verifier=type(verifier).__name__):
                wire = self.make_wire(DomainError("unauthenticated", MARKER), allow=allow, verifier=verifier)
                with patch("sys.stderr", SimpleNamespace(write=Mock(), flush=Mock())) as sink:
                    self.assert_error(wire.raw(self.body()))
                sink.write.assert_not_called()
                sink.flush.assert_not_called()

    def test_success_and_non_authentication_errors_do_not_log(self):
        for error, status in ((None, 200), (DomainError("forbidden", MARKER), 403)):
            wire = self.make_wire(error)
            with patch("sys.stderr", SimpleNamespace(write=Mock(), flush=Mock())) as sink:
                response = wire.raw(self.body())
                self.assertEqual(response.status, status)
                response.read()
            sink.write.assert_not_called()
            sink.flush.assert_not_called()

    def test_response_and_admission_release_precede_logging_failure(self):
        class Admission:
            available = 2
            def acquire(self, blocking=False):
                self.available -= 1
                return True
            def release(self):
                self.available += 1
        admission = Admission()
        with patch.object(http_api.threading, "BoundedSemaphore", return_value=admission):
            wire = self.make_wire(DomainError("unauthenticated", MARKER, diagnostic_reason="authority_expired"))
        observations = []
        def fail(message):
            observations.append((admission.available, sys.exception()))
            sent = bytes(wire.last_connection.sent)
            self.assertEqual(sent.count(b"HTTP/1.0 401"), 1)
            payload = sent.split(b'\r\n\r\n', 1)[1]
            self.assertEqual(json.loads(payload)["code"], "unauthenticated")
            raise OSError(MARKER)
        sink = SimpleNamespace(write=Mock(side_effect=fail), flush=Mock())
        with patch("sys.stderr", sink):
            self.assert_error(wire.raw(self.body()))
        self.assertEqual(observations, [(2, None)])
        self.assertEqual(admission.available, 2)
        sink.write.assert_called_once_with(expected_line("authority_expired") + '\n')
        sink.flush.assert_not_called()

    def test_control_base_exceptions_are_not_swallowed_after_response(self):
        class Control(BaseException):
            pass
        wire = self.make_wire(DomainError("unauthenticated", MARKER))
        sink = SimpleNamespace(write=Mock(side_effect=Control), flush=Mock())
        with patch("sys.stderr", sink), self.assertRaises(Control):
            wire.raw(self.body())
        self.assertEqual(bytes(wire.last_connection.sent).count(b"HTTP/1.0 401"), 1)
        sink.flush.assert_not_called()

    def test_normal_stderr_produces_one_complete_bounded_json_line(self):
        sink = io.StringIO()
        wire = self.make_wire(DomainError("unauthenticated", MARKER, diagnostic_reason="authority_expired"))
        with patch("sys.stderr", sink):
            self.assert_error(wire.raw(self.body()))
        self.assertEqual(sink.getvalue(), expected_line("authority_expired") + '\n')
        self.assertNotIn(MARKER, sink.getvalue())
        self.assertLess(len(sink.getvalue().encode()), 160)

    def test_transport_encoding_rejection_is_generic_and_categorized(self):
        wire = self.make_wire(None)
        with patch("sys.stderr", SimpleNamespace(write=Mock(), flush=Mock())) as sink:
            self.assert_error(wire.raw(self.body(encoded="%%%")), request_id=None)
        sink.write.assert_called_once_with(expected_line("authority_encoding_invalid") + "\n")
        sink.flush.assert_called_once_with()


    def test_hostile_unknown_code_keeps_legacy_reply_and_release(self):
        probes = []
        class UnknownCode(str):
            __hash__ = str.__hash__
            def __eq__(self, other):
                probes.append(other)
                if len(probes) == 1 and other == "unauthenticated":
                    raise AssertionError(MARKER)
                return str.__eq__(self, other)
        class Admission:
            available = 2
            def acquire(self, blocking=False):
                self.available -= 1
                return True
            def release(self):
                self.available += 1
        admission = Admission()
        with patch.object(http_api.threading, "BoundedSemaphore", return_value=admission):
            wire = self.make_wire(DomainError(UnknownCode("unknown-code"), MARKER))
        sink = SimpleNamespace(write=Mock(), flush=Mock())
        with patch("sys.stderr", sink):
            response = wire.raw(self.body())
            self.assertEqual(response.status, 400)
            self.assertEqual(json.loads(response.read()), {
                "schema": "runtime.error.v1", "request_id": MARKER,
                "code": "malformed_request", "detail": "Runtime request was rejected: malformed_request",
                "retryable": False})
        self.assertEqual(probes, list(ERROR_CODES))
        self.assertEqual(probes[0], "unsupported_contract")
        self.assertEqual(admission.available, 2)
        sink.write.assert_not_called()
        sink.flush.assert_not_called()

    def test_real_streamhandler_one_shot_sink_failures_cannot_leak(self):
        # Configure only the historical named logger, restored in finally.
        # Held code would invoke real StreamHandler.handleError after this failure.
        # Corrected product writes directly and never enters standard logging.
        logger = logging.getLogger(http_api.__name__)
        state = (logger.level, logger.handlers[:], logger.filters[:],
                 logger.propagate, logger.disabled)
        class Admission:
            available = 2
            def acquire(self, blocking=False):
                self.available -= 1
                return True
            def release(self):
                self.available += 1
        class OneShotSink:
            def __init__(self, failure, before):
                self.failure, self.before = failure, before
                self.buffer, self.failed = io.StringIO(), False
            def write(self, text):
                self.before()
                if self.failure == "write" and not self.failed:
                    self.failed = True
                    raise OSError(MARKER)
                return self.buffer.write(text)
            def flush(self):
                self.before()
                if self.failure == "flush" and not self.failed:
                    self.failed = True
                    raise OSError(MARKER)
        try:
            logger.setLevel(logging.WARNING)
            logger.handlers = []
            logger.filters = []
            logger.propagate = False
            logger.disabled = False
            for failure in ("write", "flush"):
                with self.subTest(failure=failure):
                    admission = Admission()
                    with patch.object(http_api.threading, "BoundedSemaphore", return_value=admission):
                        wire = self.make_wire(DomainError("unauthenticated", MARKER,
                                                        diagnostic_reason="authority_expired"))
                    observations = []
                    def before():
                        observations.append((admission.available, sys.exception()))
                        sent = bytes(wire.last_connection.sent)
                        self.assertEqual(sent.count(b"HTTP/1.0 401"), 1)
                        self.assertEqual(json.loads(sent.split(b'\r\n\r\n', 1)[1])["code"],
                                         "unauthenticated")
                    sink = OneShotSink(failure, before)
                    handler = logging.StreamHandler(sink)
                    handler.setFormatter(logging.Formatter("%(message)s"))
                    logger.handlers = [handler]
                    with patch("sys.stderr", sink), patch.object(logging, "raiseExceptions", True):
                        self.assert_error(wire.raw(self.body()))
                    self.assertTrue(sink.failed)
                    self.assertEqual(admission.available, 2)
                    self.assertTrue(observations)
                    self.assertTrue(all(available == 2 for available, _ in observations))
                    self.assertTrue(all(context is None for _, context in observations))
                    actual = sink.buffer.getvalue()
                    expected = "" if failure == "write" else expected_line("authority_expired") + '\n'
                    self.assertEqual(actual, expected)
                    for forbidden in (MARKER, "Traceback", "Logging error", "Call stack", __file__):
                        self.assertNotIn(forbidden, actual)
                    logger.handlers = []
                    handler.close()
        finally:
            logger.handlers, logger.filters = state[1], state[2]
            logger.propagate, logger.disabled = state[3], state[4]
            logger.setLevel(state[0])
