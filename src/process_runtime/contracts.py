"""Closed public v1 contracts. Authentication is supplied by an adapter, not JSON.

This module emits the distributable JSON Schema bundle. Consumers need the bundle
and generated client, never imports of runtime persistence or domain internals.
"""
from __future__ import annotations

from pathlib import Path
import json
from typing import Any

from jsonschema import Draft202012Validator, validators
from .domain import DomainError, Snapshot

StrictValidator = validators.extend(Draft202012Validator, type_checker=Draft202012Validator.TYPE_CHECKER.redefine("integer", lambda checker, value: type(value) is int))

MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_ENVELOPE_BYTES = 1024 * 1024

ID = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}(?![\\s\\S])"}
HASH = {"type": "string", "pattern": "^[a-f0-9]{64}(?![\\s\\S])"}
TEXT = {"type": "string", "minLength": 1, "maxLength": 4096}
VERSION = {"type": "integer", "minimum": 1}
TIME = {"type": "integer", "minimum": 1}
VALUES = {"type": "object", "maxProperties": 128}
STRINGS = {"type": "array", "items": ID, "uniqueItems": True, "maxItems": 128}


def obj(required: dict, optional: dict | None = None) -> dict:
    return {"type": "object", "properties": {**required, **(optional or {})},
            "required": list(required), "additionalProperties": False}


PIN = obj({"process_id": ID, "process_version": ID, "compilation_hash": HASH})
BINDING = obj({"run_id": ID, "step_id": ID, "attempt_id": ID, "fence": VERSION})
PROVENANCE = obj({"source_id": ID, "media_type": TEXT, "content_hash": HASH,
                  "parser": TEXT, "uncertainties": {"type": "array", "items": TEXT, "maxItems": 128}})
ARTIFACT = obj({"content_hash": HASH, "byte_length": {"type": "integer", "minimum": 0}, "media_type": TEXT})
VALUE_TYPE = {"oneOf": [
    obj({"kind": {"enum": ["string", "integer", "number", "boolean", "artifact"]}}),
    obj({"kind": {"const": "array"}, "items": {"$ref": "#/$defs/value_type"}}),
    obj({"kind": {"const": "object"}, "properties": {"type": "object", "additionalProperties": {"$ref": "#/$defs/value_type"}},
         "required": STRINGS}),
]}
PORTS = {"type": "object", "propertyNames": ID, "additionalProperties": {"$ref": "#/$defs/value_type"}, "maxProperties": 128}
INPUT_BINDING = {"oneOf": [
    obj({"source": {"const": "run_input"}, "name": ID}),
    obj({"source": {"const": "step_output"}, "step_id": ID, "name": ID}),
    obj({"source": {"const": "literal"}, "value": {}}),
]}
STEP = obj({"step_id": ID, "depends_on": STRINGS, "capabilities": STRINGS, "resources": STRINGS,
            "inputs": PORTS, "bindings": {"type": "object", "propertyNames": ID, "additionalProperties": INPUT_BINDING},
            "outputs": PORTS, "max_attempts": {"type": "integer", "minimum": 1, "maximum": 100}}, {"title": TEXT})
DRAFT = obj({"schema": {"const": "process.draft.v1"}, "process_id": ID, "inputs": PORTS,
             "steps": {"type": "array", "items": STEP, "minItems": 1, "maxItems": 1000}}, {"title": TEXT})

COMMANDS = {
    "process.draft.put": obj({"draft": DRAFT, "provenance": PROVENANCE}),
    "process.publish": obj({"process_id": ID, "draft_revision": VERSION, "version_id": ID}),
    "run.create": obj({"run_id": ID, "pin": PIN, "inputs": VALUES}, {"source_ref": TEXT}),
    "run.cancel": obj({"run_id": ID, "reason": TEXT}),
    "run.retry": obj({"run_id": ID, "step_id": ID, "reason": TEXT}),
    "artifact.put": obj({"artifact": ARTIFACT, "content_base64": {"type": "string", "maxLength": 1398104}}),
    "actor.register": obj({"actor_id": ID, "capabilities": STRINGS, "resources": STRINGS}, {"directory_ref": ID}),
    "actor.advertise": obj({"actor_id": ID, "capabilities": STRINGS, "resources": STRINGS}),
    "executor.claim": obj({"run_id": ID, "step_id": ID, "actor_id": ID, "lease_ms": {"type": "integer", "minimum": 1000, "maximum": 300000}}),
    "executor.heartbeat": obj({**BINDING["properties"], "lease_ms": {"type": "integer", "minimum": 1000, "maximum": 300000}}),
    "executor.complete": obj({**BINDING["properties"], "outputs": VALUES}),
    "executor.fail": obj({**BINDING["properties"], "reason": TEXT, "retryable": {"type": "boolean"}}),
    "executor.release": obj({**BINDING["properties"], "reason": TEXT}),
    "executor.effect.intent": obj({**BINDING["properties"], "effect_name": ID, "integration": ID, "request_digest": HASH, "provider_idempotent": {"type": "boolean"}}),
    "executor.effect.dispatch": obj({**BINDING["properties"], "effect_id": ID}),
    "executor.effect.observe": obj({**BINDING["properties"], "effect_id": ID, "provider_reference": TEXT, "outcome": {"enum": ["acknowledged", "succeeded", "failed", "unknown"]}, "observation_digest": HASH}),
    "effect.resolve": obj({"effect_id": ID, "outcome": {"enum": ["succeeded", "failed"]}, "provider_reference": TEXT, "observation_digest": HASH, "reason": TEXT}),
    "handoff.consume": obj({"schema": {"const": "service.runtime-handoff.v1"}, "event_id": ID, "source": TEXT,
                             "request_id": ID, "case_id": {"oneOf": [ID, {"type": "null"}]},
                             "plan_revision_id": {"oneOf": [ID, {"type": "null"}]}, "pin": PIN,
                             "inputs": VALUES, "idempotency_key": ID}),
}
QUERIES = {
    "process.get": obj({"process_id": ID}),
    "version.get": obj({"process_version": ID}),
    "run.get": obj({"run_id": ID}),
    "work.list": obj({"actor_id": ID, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}, {"after": ID}),
    "events.list": obj({"after": {"type": "integer", "minimum": 0}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}, {"run_id": ID}),
    "artifact.get": obj({"content_hash": HASH}),
    "receipt.get": obj({"receipt_id": ID}),
    "effect.get": obj({"effect_id": ID}),
    "attempt.get": obj({"run_id": ID, "step_id": ID, "attempt_id": ID}),
    "output.get": obj({"run_id": ID, "step_id": ID, "attempt_id": ID}),
}
RESOURCE_TEMPLATES = {
    "process.draft.put": "processes/{draft.process_id}", "process.publish": "processes/{process_id}",
    "process.get": "processes/{process_id}", "version.get": "versions/{process_version}",
    **{op: "runs/{run_id}" for op in ("run.create", "run.cancel", "run.retry", "run.get")},
    **{op: "runs/{run_id}/steps/{step_id}" for op in COMMANDS if op.startswith("executor.")},
    **{op: "actors/{actor_id}" for op in ("actor.register", "actor.advertise")},
    "work.list": "actors/{actor_id}/work", "artifact.put": "artifacts/{artifact.content_hash}",
    "artifact.get": "artifacts/{content_hash}", "receipt.get": "receipts/{receipt_id}",
    "output.get": "runs/{run_id}/steps/{step_id}/attempts/{attempt_id}/output",
    "attempt.get": "runs/{run_id}/steps/{step_id}/attempts/{attempt_id}",
    "effect.get": "effects/{effect_id}", "effect.resolve": "effects/{effect_id}",
    "events.list": "events-or-run-events", "handoff.consume": "source-event-sha256",
}

EVENT_KINDS = ("process.draft_updated", "process.published", "run.created", "run.cancelled", "run.retried",
               "run.succeeded", "run.failed", "run.blocked", "actor.registered", "actor.advertised",
               "attempt.claimed", "attempt.heartbeat", "attempt.completed", "attempt.failed",
               "attempt.released", "attempt.expired", "output.committed", "artifact.committed", "handoff.accepted", "effect.intent", "effect.dispatched", "effect.observed", "effect.resolved")
ERROR_CODES = ("unsupported_contract", "malformed_request", "unauthenticated", "forbidden", "replay_rejected",
               "not_found", "version_conflict", "idempotency_conflict", "invalid_dag", "type_mismatch",
               "not_ready", "capability_mismatch", "lease_expired", "stale_fence", "terminal_attempt",
               "immutable_record", "incompatible_version", "cursor_gap", "storage_unavailable", "unknown_outcome")


def schema_bundle() -> dict:
    command_variants = []
    for operation, payload in COMMANDS.items():
        command_variants.append(obj({"schema": {"const": "runtime.command.v1"}, "operation": {"const": operation},
                                     "request_id": ID, "resource": TEXT,
                                     "expected_version": ({"oneOf": [VERSION, {"type": "null"}]} if operation in ("process.draft.put", "run.create", "artifact.put", "actor.register", "handoff.consume") else VERSION), "payload": payload}))
    query_variants = [obj({"schema": {"const": "runtime.query.v1"}, "operation": {"const": operation}, "payload": payload})
                      for operation, payload in QUERIES.items()]
    event = obj({"schema": {"const": "runtime.event.v1"}, "event_id": ID, "sequence": VERSION,
                 "kind": {"enum": list(EVENT_KINDS)}, "resource": TEXT, "resource_version": VERSION,
                 "request_id": ID, "correlation_id": ID, "recorded_at_ms": TIME,
                 "data": VALUES})
    error = obj({"schema": {"const": "runtime.error.v1"}, "request_id": {"oneOf": [ID, {"type": "null"}]},
                 "code": {"enum": list(ERROR_CODES)}, "detail": TEXT, "retryable": {"type": "boolean"}},
                {"current_version": VERSION})
    result = obj({"schema": {"const": "runtime.result.v1"}, "request_id": ID,
                  "operation": {"enum": list(COMMANDS)}, "duplicate": {"type": "boolean"},
                  "resource": TEXT, "version": VERSION, "result": VALUES})
    receipt = obj({"schema": {"const": "runtime.receipt.v1"}, "receipt_id": ID, "pin": PIN, "run_id": ID,
                   "step_id": ID, "attempt_id": ID, "actor_id": ID, "input_digest": HASH,
                   "output_digest": {"oneOf": [HASH, {"type": "null"}]}, "fence": VERSION,
                   "started_at_ms": TIME, "recorded_at_ms": TIME,
                   "outcome": {"enum": ["succeeded", "failed", "released", "expired", "cancelled"]},
                   "signature": {"type": "null"}})
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "urn:zenith:process-runtime:v1",
            "$defs": {"value_type": VALUE_TYPE, "process_draft": DRAFT, "command": {"oneOf": command_variants},
                      "query": {"oneOf": query_variants}, "event": event, "error": error, "result": result,
                      "receipt": receipt, "artifact": ARTIFACT, "pin": PIN,
                      "query_result": obj({"schema": {"const": "runtime.query-result.v1"}, "operation": {"enum": list(QUERIES)}, "data": VALUES})}}


def validate(envelope: Any, kind: str) -> Snapshot:
    bundle = schema_bundle()
    if kind not in bundle["$defs"]:
        raise ValueError("Unknown contract type")
    # This also rejects NaN, tuples, non-string keys and caller-owned mutable data.
    snapshot = Snapshot.of(envelope)
    limit = MAX_REQUEST_BYTES if kind in ("command", "query") else MAX_ENVELOPE_BYTES
    if len(snapshot.text.encode("utf-8")) > limit:
        raise DomainError("malformed_request", "Envelope exceeds the public byte limit")
    selected = {**bundle, "$ref": f"#/$defs/{kind}"}
    errors = sorted(StrictValidator(selected).iter_errors(snapshot.value), key=lambda error: str(error.path))
    if errors:
        # Validation diagnostics must not echo credentials or arbitrary payloads.
        raise DomainError("malformed_request", f"Envelope does not conform to the closed {kind} contract")
    return snapshot


def command_digest(envelope: dict) -> str:
    return validate(envelope, "command").digest


def write_schema(destination: Path) -> None:
    destination.write_text(json.dumps(schema_bundle(), indent=2, ensure_ascii=False) + "\n")
