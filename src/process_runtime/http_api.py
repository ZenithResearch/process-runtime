"""Bounded loopback HTTP transport for public runtime commands and queries."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sys
import sqlite3
import threading
import time

from .contracts import ERROR_CODES, MAX_REQUEST_BYTES
from .authority import MAX_AUTHORITY_BYTES, LocalDevUntrustedVerifier
from .domain import DomainError, Snapshot

# Current SDK ensure_ascii=True expands an accepted DEL byte to six bytes.
MAX_REQUEST_ASCII_EXPANSION = 6
TRANSPORT_WRAPPER_BYTES = 66
MAX_AUTHORITY_BASE64_BYTES = 4 * ((MAX_AUTHORITY_BYTES + 2) // 3)
MAX_TRANSPORT_BYTES = MAX_REQUEST_ASCII_EXPANSION * MAX_REQUEST_BYTES + MAX_AUTHORITY_BASE64_BYTES + TRANSPORT_WRAPPER_BYTES
MAX_INFLIGHT_REQUESTS = 2
BODY_READ_SECONDS = 5
BODY_READ_CHUNK_BYTES = 65_536
ERROR_STATUS = {"unauthenticated": 401, "forbidden": 403, "not_found": 404,
                "version_conflict": 409, "idempotency_conflict": 409, "not_ready": 409,
                "stale_fence": 409, "lease_expired": 409, "replay_rejected": 409,
                "unknown_outcome": 409, "storage_unavailable": 503}


_AUTH_DIAGNOSTIC_LINES = {
    'authority_encoding_invalid': '{"event":"runtime.auth_denied","code":"unauthenticated","reason":"authority_encoding_invalid"}',
    'authority_envelope_bounds': '{"event":"runtime.auth_denied","code":"unauthenticated","reason":"authority_envelope_bounds"}',
    'authority_envelope_malformed': '{"event":"runtime.auth_denied","code":"unauthenticated","reason":"authority_envelope_malformed"}',
    'authority_expired': '{"event":"runtime.auth_denied","code":"unauthenticated","reason":"authority_expired"}',
    'authority_future': '{"event":"runtime.auth_denied","code":"unauthenticated","reason":"authority_future"}',
    'authority_lifetime_invalid': '{"event":"runtime.auth_denied","code":"unauthenticated","reason":"authority_lifetime_invalid"}',
    'authority_mode_not_admitted': '{"event":"runtime.auth_denied","code":"unauthenticated","reason":"authority_mode_not_admitted"}',
    'authority_verifier_unavailable': '{"event":"runtime.auth_denied","code":"unauthenticated","reason":"authority_verifier_unavailable"}',
    'local_dev_envelope_shape': '{"event":"runtime.auth_denied","code":"unauthenticated","reason":"local_dev_envelope_shape"}',
    'unclassified': '{"event":"runtime.auth_denied","code":"unauthenticated","reason":"unclassified"}',
    'verified_authority_malformed': '{"event":"runtime.auth_denied","code":"unauthenticated","reason":"verified_authority_malformed"}',
    'verified_authority_missing': '{"event":"runtime.auth_denied","code":"unauthenticated","reason":"verified_authority_missing"}',
}


def _emit_local_dev_auth_diagnostic(runtime, error):
    """Report a fixed local-dev category after reply/admission; never inspect evidence."""
    try:
        code = getattr(error, "code", None)
        if type(code) is not str or code != "unauthenticated":
            return
        if (getattr(runtime, "allow_local_dev", False) is not True
                or type(getattr(runtime, "verifier", None)) is not LocalDevUntrustedVerifier):
            return
        reason = getattr(error, "diagnostic_reason", None) if type(error) is DomainError else None
        if type(reason) is not str or reason not in _AUTH_DIAGNOSTIC_LINES:
            reason = "unclassified"
        stream = sys.stderr
        stream.write(_AUTH_DIAGNOSTIC_LINES[reason] + "\n")
        stream.flush()
    except Exception:
        # Telemetry cannot replace the completed generic response. Respect control exceptions.
        pass


def parse_json(raw: bytes):
    if type(raw) is not bytes or len(raw) > MAX_TRANSPORT_BYTES:
        raise DomainError("malformed_request", "Transport envelope exceeds bounds")
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
        return Snapshot.of(value).value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DomainError("malformed_request", "Expected bounded finite UTF-8 JSON without duplicate fields") from exc


def make_server(runtime, *, host="127.0.0.1", port=0):
    admissions = threading.BoundedSemaphore(MAX_INFLIGHT_REQUESTS)
    class Handler(BaseHTTPRequestHandler):
        server_version = "ProcessRuntime/0.1"
        def log_message(self, *args):
            pass
        def reply(self, status, value):
            data = Snapshot.of(value).text.encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass
        def error(self, error, request_id=None):
            code = error.code if error.code in ERROR_CODES else "malformed_request"
            self.reply(ERROR_STATUS.get(code, 400), {"schema": "runtime.error.v1", "request_id": request_id,
                       "code": code, "detail": "Runtime request was rejected: " + code,
                       "retryable": code == "storage_unavailable" or getattr(error, "retryable", False) is True})
        def do_GET(self):
            if self.path == "/live":
                self.reply(200, {"live": True, "component": "process-runtime", "contract": "runtime.v1"})
            elif self.path == "/ready":
                from .authority import DenyAllVerifier, LocalDevUntrustedVerifier
                mode = "local_dev_untrusted" if runtime.allow_local_dev and isinstance(runtime.verifier, LocalDevUntrustedVerifier) else "default_deny" if isinstance(runtime.verifier, DenyAllVerifier) else "unqualified"
                from .receiver_config import ConfiguredReceiverVerifier
                verification = runtime.verifier.verification_status() if isinstance(runtime.verifier, ConfiguredReceiverVerifier) else None
                if verification is not None:
                    mode = verification["authority"]
                try:
                    runtime.store.check_ready()
                    storage = "available"
                except Exception:
                    storage = "unavailable"
                ready = storage == "available" and mode == "local_dev_untrusted"
                checks = {"storage": storage, "authority": mode, "admission": runtime.new_run_admission.status()}
                if verification is not None:
                    checks.update(verification)
                self.reply(200 if ready else 503, {"service": "process-runtime", "ready": ready, "checks": checks})
            else:
                self.error(DomainError("not_found", "Unknown route"))
        def read_body(self, length):
            deadline = time.monotonic() + BODY_READ_SECONDS
            body = bytearray()
            while len(body) < length:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Request body deadline expired")
                self.connection.settimeout(remaining)
                chunk = self.rfile.read1(min(BODY_READ_CHUNK_BYTES, length - len(body)))
                if not chunk:
                    raise DomainError("malformed_request", "Incomplete request")
                body.extend(chunk)
            # A complete final read may resume after its socket deadline.
            if time.monotonic() >= deadline:
                raise TimeoutError("Request body deadline expired")
            # The body deadline must not become a near-zero response timeout.
            self.connection.settimeout(BODY_READ_SECONDS)
            return bytes(body)
        def do_POST(self):
            request_id = None
            admitted = False
            auth_diagnostic = None
            try:
                if self.path not in ("/v1/commands", "/v1/queries"):
                    raise DomainError("not_found", "Unknown route")
                lengths = self.headers.get_all("Content-Length", [])
                if (len(lengths) != 1 or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= MAX_TRANSPORT_BYTES
                        or self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding", "identity") != "identity"
                        or self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json"):
                    raise DomainError("malformed_request", "Invalid request framing")
                if not admissions.acquire(blocking=False):
                    raise DomainError("storage_unavailable", "Request body capacity is occupied")
                admitted = True
                raw = self.read_body(int(lengths[0]))
                transport = parse_json(raw)
                if (type(transport) is not dict or set(transport) != {"schema", "request", "authority_base64"}
                        or transport["schema"] != "runtime.transport.v1" or type(transport["authority_base64"]) is not str):
                    raise DomainError("malformed_request", "Unsupported transport envelope")
                try:
                    if len(transport["authority_base64"]) > MAX_AUTHORITY_BASE64_BYTES:
                        raise ValueError("encoded authority exceeds bounds")
                    authority = base64.b64decode(transport["authority_base64"], validate=True)
                    if len(authority) > MAX_AUTHORITY_BYTES:
                        raise ValueError("decoded authority exceeds bounds")
                except ValueError as exc:
                    raise DomainError("unauthenticated", "Malformed authority encoding",
                                      diagnostic_reason="authority_encoding_invalid") from exc
                request = transport["request"]
                if type(request) is dict:
                    supplied_id = request.get("request_id")
                    from .domain import identifier
                    try:
                        request_id = identifier(supplied_id)
                    except DomainError:
                        pass
                action = runtime.execute if self.path == "/v1/commands" else runtime.query
                result = action(request, authority)
                self.reply(200, result)
            except DomainError as error:
                auth_diagnostic = error
                self.error(error, request_id)
            except (sqlite3.Error, OSError):
                self.error(DomainError("storage_unavailable", "Storage or transport unavailable"), request_id)
            except Exception:
                self.error(DomainError("storage_unavailable", "Runtime failed safely"), request_id)
            finally:
                if admitted:
                    admissions.release()
            if auth_diagnostic is not None:
                _emit_local_dev_auth_diagnostic(runtime, auth_diagnostic)
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server
