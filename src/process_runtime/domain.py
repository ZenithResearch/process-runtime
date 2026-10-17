"""Immutable, storage-independent values and state transition rules.

No transport, credentials, SQL, clock reads, or process-specific step names belong
here. Transactional orchestration supplies verified authority and explicit time.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
import hashlib
import json
import math
import re
from typing import Any


class DomainError(ValueError):
    def __init__(self, code: str, detail: str, *, diagnostic_reason: str | None = None):
        self.code = code
        if diagnostic_reason is not None:
            self.diagnostic_reason = diagnostic_reason
        super().__init__(detail)


def identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value):
        raise DomainError("invalid_identifier", "Expected a bounded stable identifier")
    return value


def digest(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise DomainError("invalid_digest", "Expected a lowercase SHA-256 digest")
    return value


def positive(value: int, field: str) -> int:
    if type(value) is not int or value < 1:
        raise DomainError("invalid_value", f"{field} must be a positive integer")
    return value


def json_value(value: Any, depth: int = 0) -> None:
    if depth > 64:
        raise DomainError("invalid_json", "JSON nesting exceeds the supported limit")
    if type(value) is str:
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise DomainError("invalid_json", "JSON text must contain valid Unicode scalar values") from exc
        return
    if value is None or type(value) in (bool, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list:
        for item in value:
            json_value(item, depth + 1)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for key, item in value.items():
            json_value(key, depth + 1)
            json_value(item, depth + 1)
        return
    raise DomainError("invalid_json", "Only finite JSON values and string object keys are permitted")


def canonical(value: Any) -> str:
    json_value(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class Snapshot:
    """Canonical JSON bytes retained by value, never a caller-owned mutable dict."""
    text: str

    def __post_init__(self):
        if not isinstance(self.text, str):
            raise DomainError("invalid_snapshot", "Snapshot must be canonical JSON text")
        try:
            value = json.loads(self.text)
        except (TypeError, ValueError, RecursionError) as exc:
            raise DomainError("invalid_snapshot", "Malformed JSON snapshot") from exc
        if canonical(value) != self.text:
            raise DomainError("invalid_snapshot", "Snapshot is not canonical JSON")

    @classmethod
    def of(cls, value: Any) -> Snapshot:
        return cls(canonical(value))

    @property
    def value(self) -> Any:
        return json.loads(self.text)

    @property
    def digest(self) -> str:
        return sha256(self.text.encode("utf-8"))


class RunState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    BLOCKED = "blocked"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepState(StrEnum):
    WAITING = "waiting"
    READY = "ready"
    RUNNING = "running"
    BLOCKED = "blocked"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AttemptState(StrEnum):
    ACTIVE = "active"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    RELEASED = "released"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


RUN_TRANSITIONS = {
    RunState.PENDING: frozenset((RunState.RUNNING, RunState.BLOCKED, RunState.CANCELLED)),
    RunState.RUNNING: frozenset((RunState.BLOCKED, RunState.SUCCEEDED, RunState.FAILED, RunState.CANCELLED)),
    RunState.BLOCKED: frozenset((RunState.RUNNING, RunState.FAILED, RunState.CANCELLED)),
    RunState.SUCCEEDED: frozenset(), RunState.FAILED: frozenset(), RunState.CANCELLED: frozenset(),
}
STEP_TRANSITIONS = {
    StepState.WAITING: frozenset((StepState.READY, StepState.BLOCKED, StepState.CANCELLED)),
    StepState.READY: frozenset((StepState.RUNNING, StepState.BLOCKED, StepState.CANCELLED)),
    StepState.RUNNING: frozenset((StepState.SUCCEEDED, StepState.FAILED, StepState.BLOCKED, StepState.READY, StepState.CANCELLED)),
    StepState.BLOCKED: frozenset((StepState.READY, StepState.FAILED, StepState.CANCELLED)),
    StepState.SUCCEEDED: frozenset(), StepState.FAILED: frozenset(), StepState.CANCELLED: frozenset(),
}
ATTEMPT_TRANSITIONS = {
    state: frozenset(other for other in AttemptState if other != AttemptState.ACTIVE)
    if state == AttemptState.ACTIVE else frozenset() for state in AttemptState
}


def transition(state: RunState | StepState | AttemptState, target):
    tables = {RunState: RUN_TRANSITIONS, StepState: STEP_TRANSITIONS, AttemptState: ATTEMPT_TRANSITIONS}
    if type(state) not in tables or type(target) is not type(state) or target not in tables[type(state)][state]:
        raise DomainError("invalid_transition", f"Illegal {type(state).__name__} transition: {state} -> {target}")
    return target


@dataclass(frozen=True)
class ProcessDefinition:
    process_id: str
    revision: int
    draft: Snapshot
    provenance: Snapshot

    def __post_init__(self):
        identifier(self.process_id)
        positive(self.revision, "revision")
        if not isinstance(self.draft, Snapshot) or not isinstance(self.provenance, Snapshot):
            raise DomainError("invalid_snapshot", "Draft and provenance must be retained snapshots")
        if type(self.draft.value) is not dict or self.draft.value.get("process_id") != self.process_id:
            raise DomainError("process_mismatch", "Draft snapshot belongs to a different Process")

    def revise(self, *, expected_revision: int, draft: Snapshot, provenance: Snapshot):
        if type(expected_revision) is not int or expected_revision != self.revision:
            raise DomainError("version_conflict", "Draft changed since the supplied version")
        return replace(self, revision=self.revision + 1, draft=draft, provenance=provenance)


@dataclass(frozen=True)
class CompiledProcess:
    process_id: str
    snapshot: Snapshot
    compilation_hash: str

    def __post_init__(self):
        identifier(self.process_id)
        digest(self.compilation_hash)
        if not isinstance(self.snapshot, Snapshot) or self.snapshot.digest != self.compilation_hash:
            raise DomainError("compilation_mismatch", "Compiled snapshot does not match its pinned hash")
        if type(self.snapshot.value) is not dict or self.snapshot.value.get("process_id") != self.process_id:
            raise DomainError("process_mismatch", "Compiled snapshot belongs to a different Process")


@dataclass(frozen=True)
class ProcessVersion:
    version_id: str
    ordinal: int
    compiled: CompiledProcess
    source_revision: int
    published_at_ms: int

    def __post_init__(self):
        identifier(self.version_id)
        positive(self.ordinal, "ordinal")
        positive(self.source_revision, "source_revision")
        positive(self.published_at_ms, "published_at_ms")
        if not isinstance(self.compiled, CompiledProcess):
            raise DomainError("invalid_compiled_process", "A version pins a compiled process snapshot")


@dataclass(frozen=True)
class ProcessPin:
    process_id: str
    process_version: str
    compilation_hash: str

    def __post_init__(self):
        identifier(self.process_id)
        identifier(self.process_version)
        digest(self.compilation_hash)

    @classmethod
    def of(cls, version: ProcessVersion):
        return cls(version.compiled.process_id, version.version_id, version.compiled.compilation_hash)


@dataclass(frozen=True)
class Actor:
    actor_id: str
    capabilities: tuple[str, ...]
    resources: tuple[str, ...] = ()
    directory_ref: str | None = None

    def __post_init__(self):
        identifier(self.actor_id)
        for values in (self.capabilities, self.resources):
            if type(values) is not tuple:
                raise DomainError("invalid_capability", "Capabilities and resources must be unique immutable tuples")
            for value in values:
                identifier(value)
            if len(values) != len(set(values)):
                raise DomainError("invalid_capability", "Capabilities and resources must be unique immutable tuples")
        if self.directory_ref is not None:
            identifier(self.directory_ref)

    def missing(self, capabilities: tuple[str, ...], resources: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({f"capability:{x}" for x in set(capabilities) - set(self.capabilities)} |
                            {f"resource:{x}" for x in set(resources) - set(self.resources)}))


@dataclass(frozen=True)
class ProcessRun:
    run_id: str
    pin: ProcessPin
    inputs: Snapshot
    state: RunState = RunState.PENDING
    version: int = 1
    source_ref: str | None = None

    def __post_init__(self):
        identifier(self.run_id)
        positive(self.version, "version")
        if not isinstance(self.pin, ProcessPin) or not isinstance(self.inputs, Snapshot) or type(self.state) is not RunState:
            raise DomainError("invalid_run", "Runs require an exact version pin, input snapshot and typed state")
        if self.source_ref is not None and (not isinstance(self.source_ref, str) or not self.source_ref or len(self.source_ref) > 4096):
            raise DomainError("invalid_source", "Origin is an optional opaque bounded reference")

    def move(self, target: RunState):
        return replace(self, state=transition(self.state, target), version=self.version + 1)


@dataclass(frozen=True)
class StepRun:
    run_id: str
    step_id: str
    state: StepState = StepState.WAITING
    fence: int = 0
    current_attempt: str | None = None

    def __post_init__(self):
        identifier(self.run_id)
        identifier(self.step_id)
        if type(self.state) is not StepState or type(self.fence) is not int or self.fence < 0:
            raise DomainError("invalid_step", "Step state and monotonic fence are invalid")
        if self.current_attempt is not None:
            identifier(self.current_attempt)
        if self.state == StepState.RUNNING and (not self.current_attempt or self.fence == 0):
            raise DomainError("unclaimed_step", "A running step needs its claimed Attempt and positive fence")


@dataclass(frozen=True)
class Attempt:
    attempt_id: str
    run_id: str
    step_id: str
    ordinal: int
    actor_id: str
    input_digest: str
    fence: int
    started_at_ms: int
    state: AttemptState = AttemptState.ACTIVE

    def __post_init__(self):
        for value in (self.attempt_id, self.run_id, self.step_id, self.actor_id):
            identifier(value)
        for name in ("ordinal", "fence", "started_at_ms"):
            positive(getattr(self, name), name)
        digest(self.input_digest)
        if type(self.state) is not AttemptState:
            raise DomainError("invalid_attempt", "Attempt state must be typed")

    def move(self, target: AttemptState):
        return replace(self, state=transition(self.state, target))


@dataclass(frozen=True)
class Lease:
    run_id: str
    step_id: str
    attempt_id: str
    actor_id: str
    fence: int
    expires_at_ms: int

    def __post_init__(self):
        for value in (self.run_id, self.step_id, self.attempt_id, self.actor_id):
            identifier(value)
        positive(self.fence, "fence")
        positive(self.expires_at_ms, "expires_at_ms")

    def require_current(self, attempt: Attempt, *, now_ms: int, current_fence: int):
        binding = (self.run_id, self.step_id, self.attempt_id, self.actor_id, self.fence)
        expected = (attempt.run_id, attempt.step_id, attempt.attempt_id, attempt.actor_id, attempt.fence)
        if binding != expected or type(current_fence) is not int or current_fence != self.fence:
            raise DomainError("stale_fence", "Lease is not bound to the current Attempt and Actor")
        if type(now_ms) is not int or now_ms < attempt.started_at_ms or now_ms >= self.expires_at_ms:
            raise DomainError("lease_expired", "Lease is expired or time moved behind this Attempt")
        if attempt.state != AttemptState.ACTIVE:
            raise DomainError("terminal_attempt", "A terminal Attempt cannot commit again")


@dataclass(frozen=True)
class ArtifactRef:
    content_hash: str
    byte_length: int
    media_type: str

    def __post_init__(self):
        digest(self.content_hash)
        if type(self.byte_length) is not int or self.byte_length < 0:
            raise DomainError("invalid_artifact", "Artifact length must be nonnegative")
        if not isinstance(self.media_type, str) or not re.fullmatch(r"[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+", self.media_type):
            raise DomainError("invalid_artifact", "Artifact media type is invalid")

    def verify(self, content: bytes):
        if type(content) is not bytes or len(content) != self.byte_length or sha256(content) != self.content_hash:
            raise DomainError("artifact_mismatch", "Artifact bytes do not match the immutable reference")


@dataclass(frozen=True)
class OutputCommit:
    commit_id: str
    run_id: str
    step_id: str
    attempt_id: str
    fence: int
    values: Snapshot
    output_digest: str
    committed_at_ms: int

    def __post_init__(self):
        for value in (self.commit_id, self.run_id, self.step_id, self.attempt_id):
            identifier(value)
        positive(self.fence, "fence")
        positive(self.committed_at_ms, "committed_at_ms")
        digest(self.output_digest)
        if not isinstance(self.values, Snapshot) or type(self.values.value) is not dict or self.values.digest != self.output_digest:
            raise DomainError("output_mismatch", "Output commit requires a matching immutable output object")

    def require_attempt(self, attempt: Attempt):
        if (self.run_id, self.step_id, self.attempt_id, self.fence) != (attempt.run_id, attempt.step_id, attempt.attempt_id, attempt.fence):
            raise DomainError("attempt_mismatch", "Output commit belongs to a different Attempt")


@dataclass(frozen=True)
class Receipt:
    receipt_id: str
    pin: ProcessPin
    run_id: str
    step_id: str
    attempt_id: str
    actor_id: str
    input_digest: str
    output_digest: str | None
    fence: int
    started_at_ms: int
    recorded_at_ms: int
    outcome: AttemptState
    signature: Snapshot | None = None

    def __post_init__(self):
        for value in (self.receipt_id, self.run_id, self.step_id, self.attempt_id, self.actor_id):
            identifier(value)
        if not isinstance(self.pin, ProcessPin):
            raise DomainError("invalid_receipt", "Receipt requires the immutable process pin")
        digest(self.input_digest)
        if self.output_digest is not None:
            digest(self.output_digest)
        for name in ("fence", "started_at_ms", "recorded_at_ms"):
            positive(getattr(self, name), name)
        if type(self.outcome) is not AttemptState or self.outcome == AttemptState.ACTIVE or self.recorded_at_ms < self.started_at_ms:
            raise DomainError("invalid_receipt", "Receipt must record a terminal Attempt outcome and ordered timestamps")
        if self.outcome == AttemptState.SUCCEEDED and self.output_digest is None:
            raise DomainError("missing_output", "Success cannot precede its immutable output commit")
        if self.signature is not None:
            raise DomainError("signature_not_implemented", "MVP receipts are unsigned; a reserved field is not signature verification")
