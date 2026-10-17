"""Receiver-owned authority policy and native secS schema-4 verification adapter.

No credentials are accepted from command JSON. Native verification binds the
actual bincode context and packet; replay and current fencing are checked in the
same transaction as the runtime mutation by the application.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Callable

from .contracts import MAX_REQUEST_BYTES, validate
from .domain import DomainError, Snapshot, digest, identifier, positive
from .ports import VerifiedAuthority

DEFAULT_AUDIENCE = "runtime://receiver-local"
OPCODES = {
    "process.draft.put": 0x40, "process.publish": 0x41, "run.create": 0x42,
    "run.cancel": 0x43, "run.retry": 0x44, "artifact.put": 0x45,
    "actor.register": 0x46, "actor.advertise": 0x47, "executor.claim": 0x48,
    "executor.heartbeat": 0x49, "executor.complete": 0x4A, "executor.fail": 0x4B,
    "executor.release": 0x4C, "handoff.consume": 0x4D,
    "executor.effect.intent": 0x4E, "executor.effect.dispatch": 0x4F,
    "executor.effect.observe": 0x50, "effect.resolve": 0x51,
    "process.get": 0x60, "version.get": 0x61, "run.get": 0x62,
    "work.list": 0x63, "events.list": 0x64, "artifact.get": 0x65,
    "receipt.get": 0x66, "output.get": 0x67, "effect.get": 0x68, "attempt.get": 0x69,
}
MAX_AUTHORITY_BYTES = 4_400_000
MAX_CONTEXT_MS = 60_000
MAX_NATIVE_PROOF_BYTES = 16_384
NATIVE_PACKET_FIXED_BYTES = 69
MAX_NATIVE_PACKET_BYTES = MAX_REQUEST_BYTES + MAX_NATIVE_PROOF_BYTES + NATIVE_PACKET_FIXED_BYTES
MAX_NATIVE_CONTEXT_BYTES = 65_536
MAX_NATIVE_METADATA_BYTES = 65_536
MAX_NATIVE_INPUT_BYTES = 9 * 1024 * 1024
MAX_NATIVE_OUTPUT_BYTES = 131_072


def _request(snapshot: Snapshot) -> dict:
    if not isinstance(snapshot, Snapshot):
        raise DomainError("malformed_request", "Expected retained request snapshot")
    body = snapshot.value
    if type(body) is not dict or body.get("schema") not in ("runtime.command.v1", "runtime.query.v1"):
        raise DomainError("malformed_request", "Unsupported request envelope")
    validate(body, "command" if body["schema"] == "runtime.command.v1" else "query")
    if body["operation"] not in OPCODES:
        raise DomainError("unsupported_contract", "Operation has no receiver-local opcode")
    return body


def operation_name(snapshot: Snapshot) -> str:
    return f"runtime.{_request(snapshot)['operation']}.v1"


def resource_for(snapshot: Snapshot) -> str:
    body = _request(snapshot)
    op, p = body["operation"], body["payload"]
    if op == "process.draft.put":
        return f"processes/{p['draft']['process_id']}"
    if op in ("process.publish", "process.get"):
        return f"processes/{p['process_id']}"
    if op == "version.get":
        return f"versions/{p['process_version']}"
    if op in ("run.create", "run.cancel", "run.retry", "run.get"):
        return f"runs/{p['run_id']}"
    if op.startswith("executor."):
        return f"runs/{p['run_id']}/steps/{p['step_id']}"
    if op in ("actor.register", "actor.advertise"):
        return f"actors/{p['actor_id']}"
    if op == "work.list":
        return f"actors/{p['actor_id']}/work"
    if op == "artifact.put":
        return f"artifacts/{p['artifact']['content_hash']}"
    if op == "artifact.get":
        return f"artifacts/{p['content_hash']}"
    if op == "receipt.get":
        return f"receipts/{p['receipt_id']}"
    if op == "output.get":
        return f"runs/{p['run_id']}/steps/{p['step_id']}/attempts/{p['attempt_id']}/output"
    if op == "attempt.get":
        return f"runs/{p['run_id']}/steps/{p['step_id']}/attempts/{p['attempt_id']}"
    if op in ("effect.resolve", "effect.get"):
        return f"effects/{p['effect_id']}"
    if op == "events.list":
        return f"runs/{p['run_id']}/events" if "run_id" in p else "events"
    if op == "handoff.consume":
        return "handoffs/" + Snapshot.of({"source": p["source"], "event_id": p["event_id"]}).digest
    raise DomainError("unsupported_contract", "No resource projection for this operation")


required_resource = resource_for


def _hex(value, length: int) -> bool:
    return type(value) is str and re.fullmatch(f"[a-f0-9]{{{length}}}", value) is not None


def authorize_binding(verified: VerifiedAuthority, snapshot: Snapshot, now_ms: int,
                      allow_local_dev: bool = False, expected_audience: str = DEFAULT_AUDIENCE) -> None:
    body = _request(snapshot)
    if not isinstance(verified, VerifiedAuthority):
        raise DomainError("unauthenticated", "No verified authority was supplied", diagnostic_reason="verified_authority_missing")
    try:
        identifier(verified.subject_id); identifier(verified.key_id)
        digest(verified.request_digest); digest(verified.descriptor_fingerprint)
        positive(now_ms, "now_ms"); positive(verified.issued_at_ms, "issued_at_ms")
        positive(verified.expires_at_ms, "expires_at_ms")
    except DomainError as exc:
        raise DomainError("unauthenticated", "Malformed verified authority", diagnostic_reason="verified_authority_malformed") from exc
    if verified.mode != "production_verified" and not (
            allow_local_dev is True and verified.mode == "local_dev_untrusted"):
        raise DomainError("unauthenticated", "Authority mode is not admitted by this receiver", diagnostic_reason="authority_mode_not_admitted")
    if (verified.audience != expected_audience or verified.operation != body["operation"]
            or verified.resource != resource_for(snapshot) or verified.request_digest != snapshot.digest
            or type(verified.opcode) is not int or verified.opcode != OPCODES[body["operation"]]
            or not _hex(verified.session_id, 32) or not _hex(verified.nonce, 24)):
        raise DomainError("forbidden", "Authority does not bind this exact request")
    if body["schema"] == "runtime.command.v1" and body["resource"] != verified.resource:
        raise DomainError("forbidden", "Command resource differs from its canonical payload resource")
    if not (verified.issued_at_ms <= now_ms < verified.expires_at_ms
            and 0 < verified.expires_at_ms - verified.issued_at_ms <= MAX_CONTEXT_MS):
        if not 0 < verified.expires_at_ms - verified.issued_at_ms <= MAX_CONTEXT_MS:
            reason = "authority_lifetime_invalid"
        elif now_ms < verified.issued_at_ms:
            reason = "authority_future"
        else:
            reason = "authority_expired"
        raise DomainError("unauthenticated", "Authority is expired, future dated or exceeds lifetime",
                          diagnostic_reason=reason)


def _object(envelope: bytes) -> dict:
    if type(envelope) is not bytes or len(envelope) > MAX_AUTHORITY_BYTES:
        raise DomainError("unauthenticated", "Authority envelope exceeds bounds", diagnostic_reason="authority_envelope_bounds")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    try:
        value = json.loads(envelope.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
        if type(value) is not dict:
            raise ValueError("not object")
        Snapshot.of(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DomainError("unauthenticated", "Malformed authority envelope", diagnostic_reason="authority_envelope_malformed") from exc


class DenyAllVerifier:
    def verify(self, *, envelope: bytes, command: Snapshot, now_ms: int) -> VerifiedAuthority:
        raise DomainError("unauthenticated", "No qualified receiver authority adapter is configured", diagnostic_reason="authority_verifier_unavailable")


def local_dev_envelope(command: Snapshot, *, now_ms: int, session_id: str, nonce: str,
                       ttl_ms: int = MAX_CONTEXT_MS) -> bytes:
    _request(command)
    positive(now_ms, "now_ms")
    if type(ttl_ms) is not int or not 1 <= ttl_ms <= MAX_CONTEXT_MS or not _hex(session_id, 32) or not _hex(nonce, 24):
        raise DomainError("malformed_request", "Invalid explicit local development envelope")
    return Snapshot.of({"schema": "runtime.local-dev-envelope.v1", "session_id": session_id,
                        "nonce": nonce, "issued_at_ms": now_ms,
                        "expires_at_ms": now_ms + ttl_ms}).text.encode()


class LocalDevUntrustedVerifier:
    """Explicit development adapter. Caller cannot choose its configured subject."""
    def __init__(self, subject_id: str, *, audience: str = DEFAULT_AUDIENCE):
        self.subject_id = identifier(subject_id)
        self.audience = audience

    def verify(self, *, envelope: bytes, command: Snapshot, now_ms: int) -> VerifiedAuthority:
        body = _request(command)
        value = _object(envelope)
        if set(value) != {"schema", "session_id", "nonce", "issued_at_ms", "expires_at_ms"} or value["schema"] != "runtime.local-dev-envelope.v1":
            raise DomainError("unauthenticated", "Expected explicit local development authority", diagnostic_reason="local_dev_envelope_shape")
        verified = VerifiedAuthority(self.subject_id, "local-dev", self.audience, body["operation"],
            resource_for(command), command.digest, value["issued_at_ms"], value["expires_at_ms"],
            value["session_id"], OPCODES[body["operation"]], value["nonce"],
            Snapshot.of({"mode": "local_dev_untrusted", "operation": operation_name(command)}).digest,
            "local_dev_untrusted")
        authorize_binding(verified, command, now_ms, allow_local_dev=True, expected_audience=self.audience)
        return verified


@dataclass(frozen=True)
class VerifierKey:
    key_id: str
    public_key_hex: str
    status: str = "active"
    production_authority: bool = True
    not_before: int | None = None
    not_after: int | None = None
    revoked_at: int | None = None

    def __post_init__(self):
        identifier(self.key_id)
        if not _hex(self.public_key_hex, 64) or self.status not in ("active", "revoked", "expired") or type(self.production_authority) is not bool:
            raise ValueError("Invalid receiver verifier key")
        for value in (self.not_before, self.not_after, self.revoked_at):
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError("Key windows use integer Unix seconds")


@dataclass(frozen=True)
class PermissionRule:
    subject_id: str
    operation: str
    resource: str
    effect: str
    not_before_ms: int
    not_after_ms: int
    resource_match: str = "exact"
    key_id: str | None = None
    active: bool = True

    def __post_init__(self):
        identifier(self.subject_id)
        if self.key_id is not None:
            identifier(self.key_id)
        if (self.operation not in {f"runtime.{op}.v1" for op in OPCODES}
                or self.effect not in ("allow", "deny") or type(self.resource) is not str
                or not 1 <= len(self.resource) <= 4096 or any(ord(c) < 32 for c in self.resource)
                or "*" in self.resource or self.resource_match not in ("exact", "prefix")
                or (self.resource_match == "prefix" and not self.resource.endswith("/"))
                or type(self.active) is not bool
                or type(self.not_before_ms) is not int or type(self.not_after_ms) is not int
                or not 0 <= self.not_before_ms < self.not_after_ms):
            raise ValueError("Invalid exact or explicit prefix receiver permission")


@dataclass(frozen=True)
class ReceiverPolicy:
    audience: str
    keys: tuple[VerifierKey, ...]
    # (full operation name, native active-manifest fingerprint, handler id).
    descriptors: tuple[tuple[str, str, str], ...]
    rules: tuple[PermissionRule, ...]
    revoked_subject_keys: frozenset[tuple[str, str]] = frozenset()

    def __post_init__(self):
        if (type(self.audience) is not str or not self.audience or type(self.keys) is not tuple
                or type(self.rules) is not tuple or type(self.descriptors) is not tuple
                or type(self.revoked_subject_keys) is not frozenset
                or not all(isinstance(key, VerifierKey) for key in self.keys)
                or not all(isinstance(rule, PermissionRule) for rule in self.rules)):
            raise ValueError("Receiver policy must be immutable and explicit")
        names = set()
        for name, fingerprint, handler in self.descriptors:
            if name in names or name not in {f"runtime.{op}.v1" for op in OPCODES}:
                raise ValueError("Duplicate or unsupported receiver descriptor")
            names.add(name); digest(fingerprint); identifier(handler)
        for subject, key in self.revoked_subject_keys:
            identifier(subject); identifier(key)

    def require_permission(self, subject: str, key: str, operation: str, resource: str, now_ms: int) -> None:
        if (subject, key) in self.revoked_subject_keys:
            raise DomainError("forbidden", "Subject key is revoked")
        matching = [rule for rule in self.rules if rule.active and rule.subject_id == subject
                    and (rule.key_id is None or rule.key_id == key) and rule.operation == operation
                    and rule.not_before_ms <= now_ms < rule.not_after_ms
                    and (rule.resource == resource if rule.resource_match == "exact" else resource.startswith(rule.resource))]
        if not any(rule.effect == "allow" for rule in matching) or any(rule.effect == "deny" for rule in matching):
            raise DomainError("forbidden", "Receiver permissions deny this operation and resource")


class NativeSecSHelper:
    """Pinned verification-only executable; never an issuer or native Wallet CLI."""
    def __init__(self, executable: Path, sha256: str):
        self.executable = Path(executable)
        self.sha256 = digest(sha256)
        if not self.executable.is_absolute():
            raise ValueError("Native verifier path must be absolute")

    def verify(self, value: dict) -> dict:
        try:
            if self.executable.is_symlink() or hashlib.sha256(self.executable.read_bytes()).hexdigest() != self.sha256:
                raise ValueError("unqualified helper bytes")
            raw = Snapshot.of(value).text.encode()
            metadata = {**value, "packet_hex": "", "request_hex": "", "signed_context_hex": ""}
            if len(raw) > MAX_NATIVE_INPUT_BYTES or len(Snapshot.of(metadata).text.encode()) > MAX_NATIVE_METADATA_BYTES:
                raise ValueError("native verifier input exceeds bounds")
            result = subprocess.run([str(self.executable)], input=raw,
                                    capture_output=True, timeout=5, env={}, check=False)
            if result.returncode != 0 or result.stderr or len(result.stdout) > MAX_NATIVE_OUTPUT_BYTES:
                raise ValueError("native verifier rejected")
            output = _object(result.stdout)
            if set(output) != {"schema", "context", "signer_key_id", "authenticator_kind"} or output["schema"] != "process-runtime.secs-check-output.v1":
                raise ValueError("native verifier response mismatch")
            return output
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise DomainError("unauthenticated", "Native secS verification unavailable or rejected") from exc


class SecSExecutionAuthorityVerifier:
    def __init__(self, native_helper: NativeSecSHelper | None = None,
                 load_policy: Callable[[], ReceiverPolicy] | None = None):
        self.native_helper, self.load_policy = native_helper, load_policy

    def verify(self, *, envelope: bytes, command: Snapshot, now_ms: int) -> VerifiedAuthority:
        if self.native_helper is None or self.load_policy is None:
            return DenyAllVerifier().verify(envelope=envelope, command=command, now_ms=now_ms)
        body = _request(command)
        positive(now_ms, "now_ms")
        supplied = _object(envelope)
        if set(supplied) != {"schema", "packet_hex", "signed_context_hex"} or supplied["schema"] != "runtime.secs-envelope.v1":
            raise DomainError("unauthenticated", "Unsupported native authority envelope")
        for name, limit in (("packet_hex", MAX_NATIVE_PACKET_BYTES), ("signed_context_hex", MAX_NATIVE_CONTEXT_BYTES)):
            raw = supplied[name]
            if (type(raw) is not str or len(raw) > 2 * limit or len(raw) % 2
                    or re.fullmatch(r"[0-9a-f]*", raw) is None):
                raise DomainError("unauthenticated", "Native authority requires bounded exact bincode bytes")
        try:
            policy = self.load_policy()  # Reload revocation, keys and grants on every invocation.
        except Exception as exc:
            raise DomainError("unauthenticated", "Receiver policy unavailable") from exc
        if not isinstance(policy, ReceiverPolicy):
            raise DomainError("unauthenticated", "Receiver policy unavailable")
        output = self.native_helper.verify({"schema": "process-runtime.secs-check-input.v1",
            "packet_hex": supplied["packet_hex"], "signed_context_hex": supplied["signed_context_hex"],
            "request_hex": command.text.encode().hex(), "audience": policy.audience,
            "now_seconds": now_ms // 1000, "keys": [asdict(key) for key in policy.keys]})
        try:
            c = output["context"]
            name = operation_name(command)
            descriptor = next((entry for entry in policy.descriptors if entry[0] == name), None)
            if (output["authenticator_kind"] != "ed25519_node_and_verifier" or c["schema_version"] != 4
                    or c["operation"] != name or c["resource"] != resource_for(command)
                    or descriptor is None or c["descriptor_fingerprint"] not in (
                        descriptor[1], "descriptor:sha256:" + descriptor[1])
                    or c["handler_id"] != descriptor[2] or c["replay_scope"] != "session:opcode:nonce"):
                raise ValueError("descriptor mismatch")
            verified = VerifiedAuthority(c["subject"]["subject_id"], c["subject"]["key_id"], c["audience"],
                body["operation"], c["resource"], command.digest, c["issued_at"] * 1000, c["expires_at"] * 1000,
                # The helper authenticated the original native context bytes.
                # Normalize only the exact current descriptor into our existing
                # digest-only internal authority; never rewrite signed bytes.
                bytes(c["session_id"]).hex(), c["opcode"], bytes(c["nonce"]).hex(), descriptor[1], "production_verified")
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise DomainError("unauthenticated", "Native verified context is incompatible with this receiver") from exc
        authorize_binding(verified, command, now_ms, expected_audience=policy.audience)
        policy.require_permission(verified.subject_id, verified.key_id, name, verified.resource, now_ms)
        return verified
