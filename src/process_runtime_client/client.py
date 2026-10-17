"""Public wire-only client. No process_runtime implementation imports."""
from __future__ import annotations
import base64
from importlib.resources import files
import json
import hashlib
import re
import secrets
import time
from typing import Callable
from urllib import error, parse, request
from jsonschema import Draft202012Validator, validators

SCHEMA = json.loads(files("process_runtime_client").joinpath("runtime-v1.schema.json").read_text())
RESOURCE_TEMPLATES = json.loads(files("process_runtime_client").joinpath("resource-templates-v1.json").read_text())
MAX_RESPONSE_BYTES = 4_500_000
StrictValidator = validators.extend(Draft202012Validator, type_checker=Draft202012Validator.TYPE_CHECKER.redefine("integer", lambda checker, value: type(value) is int))


class RuntimeClientError(RuntimeError):
    def __init__(self, code, *, retryable=False, uncertain=False, current_version=None):
        self.code, self.retryable, self.uncertain, self.current_version = code, retryable, uncertain, current_version
        super().__init__("Runtime request failed: " + code)


def validate_wire(value, kind):
    schema = {**SCHEMA, "$ref": "#/$defs/" + kind}
    if not StrictValidator(schema).is_valid(value):
        raise RuntimeClientError("incompatible_version")
    return value


def exact_retry(command: dict) -> dict:
    """Return identical intent, including request ID and version; never auto-rebase."""
    return json.loads(json.dumps(validate_wire(command, "command"), allow_nan=False))


def resource_for(envelope: dict) -> str:
    """Canonical exact resource from generated contract metadata, never caller hints."""
    operation, payload = envelope["operation"], envelope["payload"]
    template = RESOURCE_TEMPLATES[operation]
    if template == "events-or-run-events":
        return "runs/" + payload["run_id"] + "/events" if "run_id" in payload else "events"
    if template == "source-event-sha256":
        raw = json.dumps({"source":payload["source"], "event_id":payload["event_id"]}, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
        return "handoffs/" + hashlib.sha256(raw).hexdigest()
    def value(match):
        selected = payload
        for part in match.group(1).split("."):
            selected = selected[part]
        return selected
    return re.sub(r"\{([^}]+)\}", value, template)


def command_envelope(operation: str, *, request_id: str, expected_version: int | None, payload: dict) -> dict:
    envelope = {"schema":"runtime.command.v1", "operation":operation, "request_id":request_id,
                "resource":"pending", "expected_version":expected_version, "payload":payload}
    validate_wire(envelope, "command")
    envelope["resource"] = resource_for(envelope)
    return envelope


class LocalDevAuthority:
    """Explicit non-authoritative test/development proof; never a production signer."""
    def __init__(self, *, environment: str, session_id: str | None = None):
        if environment not in ("development", "test"):
            raise ValueError("Local development evidence is prohibited in production")
        self.session_id = session_id or secrets.token_hex(16)
    def __call__(self, request_body: dict) -> bytes:
        now = time.time_ns() // 1_000_000
        return json.dumps({"schema": "runtime.local-dev-envelope.v1", "session_id": self.session_id,
                           "nonce": secrets.token_hex(12), "issued_at_ms": now, "expires_at_ms": now + 60000},
                          sort_keys=True, separators=(",", ":")).encode()


class RuntimeClient:
    def __init__(self, endpoint: str, *, authority: Callable[[dict], bytes] | None = None, timeout=10):
        url = parse.urlsplit(endpoint)
        if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
            raise ValueError("Expected a fixed credential-free runtime origin")
        if url.scheme == "http" and url.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("Plain HTTP is restricted to loopback development")
        self.endpoint, self.authority, self.timeout = endpoint.rstrip("/"), authority, timeout
        class NoRedirect(request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        self.opener = request.build_opener(request.ProxyHandler({}), NoRedirect())

    def execute(self, command: dict, evidence: bytes | None = None) -> dict:
        return self._send("commands", validate_wire(command, "command"), evidence)

    def query(self, query: dict, evidence: bytes | None = None) -> dict:
        return self._send("queries", validate_wire(query, "query"), evidence)

    def event_pages(self, *, after: int = 0, limit: int = 100, max_pages: int = 100):
        """Bounded cursor replay; consumers persist the last applied cursor themselves."""
        if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 100 or type(max_pages) is not int or not 1 <= max_pages <= 1000:
            raise ValueError("Invalid subscription bounds")
        cursor = after
        for _ in range(max_pages):
            response = self.query({"schema":"runtime.query.v1", "operation":"events.list", "payload":{"after":cursor,"limit":limit}})
            page = response["data"]
            try:
                if set(page) != {"events","next_cursor","high_watermark"} or type(page["events"]) is not list or len(page["events"]) > limit:
                    raise ValueError()
                if type(page["next_cursor"]) is not int or type(page["high_watermark"]) is not int or not cursor <= page["next_cursor"] <= page["high_watermark"]:
                    raise ValueError()
                sequence = cursor
                seen = set()
                for event in page["events"]:
                    validate_wire(event,"event")
                    sequence += 1
                    if event["sequence"] != sequence or event["event_id"] in seen:
                        raise ValueError()
                    seen.add(event["event_id"])
                if page["next_cursor"] != sequence or (not page["events"] and cursor != page["high_watermark"]):
                    raise ValueError()
            except (KeyError, TypeError, ValueError, RuntimeClientError):
                raise RuntimeClientError("cursor_gap") from None
            yield page
            cursor = page["next_cursor"]
            if cursor == page["high_watermark"]:
                return

    def _send(self, path, body, evidence):
        if evidence is None:
            if self.authority is None:
                raise RuntimeClientError("unauthenticated")
            evidence = self.authority(body)
        if type(evidence) is not bytes:
            raise RuntimeClientError("unauthenticated")
        payload = json.dumps({"schema": "runtime.transport.v1", "request": body,
                              "authority_base64": base64.b64encode(evidence).decode()}, allow_nan=False, separators=(",", ":")).encode()
        call = request.Request(self.endpoint + "/v1/" + path, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with self.opener.open(call, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise RuntimeClientError("incompatible_version", uncertain=path == "commands")
                value = json.loads(raw)
                try:
                    validate_wire(value, "result" if path == "commands" else "query_result")
                    if value["operation"] != body["operation"] or (path == "commands" and (value["request_id"] != body["request_id"] or value["resource"] != body["resource"])):
                        raise RuntimeClientError("incompatible_version")
                except RuntimeClientError:
                    raise RuntimeClientError("incompatible_version", uncertain=path == "commands") from None
                return value
        except error.HTTPError as exc:
            try:
                value = validate_wire(json.loads(exc.read(MAX_RESPONSE_BYTES)), "error")
            except Exception:
                raise RuntimeClientError("incompatible_version", uncertain=path == "commands") from None
            raise RuntimeClientError(value["code"], retryable=value["retryable"], current_version=value.get("current_version")) from None
        except (error.URLError, TimeoutError, OSError):
            raise RuntimeClientError("transport_unavailable", retryable=True, uncertain=path == "commands") from None
        except (ValueError, UnicodeError):
            raise RuntimeClientError("incompatible_version", uncertain=path == "commands") from None
