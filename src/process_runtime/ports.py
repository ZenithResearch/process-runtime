"""Application-owned persistence and authority boundaries.

Adapters implement these ports. Domain objects contain no connection, row, SQL,
HTTP, key custody, or event-bus API. An external bus is only a wake-up hint.
"""
from __future__ import annotations
from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .domain import Snapshot


class RecordKind(StrEnum):
    PROCESS_DEFINITION = "process_definition"
    PROCESS_VERSION = "process_version"
    PROCESS_RUN = "process_run"
    STEP_RUN = "step_run"
    ATTEMPT = "attempt"
    LEASE = "lease"
    ACTOR = "actor_registration"
    OUTPUT_COMMIT = "output_commit"
    ARTIFACT = "artifact"
    RECEIPT = "receipt"
    EFFECT = "external_effect"
    INBOX = "inbox"
    OUTBOX = "outbox"


@dataclass(frozen=True)
class Record:
    kind: RecordKind
    record_id: str
    version: int
    value: Snapshot


@dataclass(frozen=True)
class RequestResult:
    subject_id: str
    request_id: str
    request_digest: str
    response: Snapshot


class Transaction(Protocol):
    def get(self, kind: RecordKind, record_id: str) -> Record | None: ...
    def scan(self, kind: RecordKind, *, after: str | None, limit: int) -> tuple[Record, ...]: ...
    def insert(self, record: Record) -> None: ...
    def replace(self, record: Record, *, expected_version: int) -> None: ...
    def request_result(self, subject_id: str, request_id: str) -> RequestResult | None: ...
    def record_result(self, result: RequestResult) -> None: ...
    def append_event(self, event: Snapshot) -> int: ...
    def admit_replay(self, *, subject_id: str, session_id: str, opcode: int, nonce: str, expires_at_ms: int) -> None: ...


class RuntimeStore(Protocol):
    def transaction(self) -> AbstractContextManager[Transaction]: ...
    def get(self, kind: RecordKind, record_id: str) -> Record | None: ...
    def events(self, *, after: int, limit: int) -> tuple[Snapshot, ...]: ...
    def event_high_watermark(self) -> int: ...
    def check_ready(self) -> None: ...
    def check_integrity(self) -> None: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class VerifiedAuthority:
    """Adapter output, never decoded from an unauthenticated caller's JSON.

    A Rolodex Actor reference is intentionally absent. Actor ownership is checked
    against this subject by the application after receiver-local authorization.
    """
    subject_id: str
    key_id: str
    audience: str
    operation: str
    resource: str
    request_digest: str
    issued_at_ms: int
    expires_at_ms: int
    session_id: str
    opcode: int
    nonce: str
    descriptor_fingerprint: str
    mode: str


class ExecutionAuthorityVerifier(Protocol):
    def verify(self, *, envelope: bytes, command: Snapshot, now_ms: int) -> VerifiedAuthority: ...


class WakeupHints(Protocol):
    def notify(self, event_sequence: int) -> None: ...
