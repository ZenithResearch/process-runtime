"""Pure, deterministic compilation of the closed process.draft.v1 contract.

This module validates data and builds immutable values; publication storage,
authorization, clocks and scheduling belong to application services.
"""
from __future__ import annotations

from dataclasses import dataclass
import heapq
import math
from typing import Any

from jsonschema import Draft202012Validator

from .contracts import PROVENANCE, validate
from .domain import (
    ArtifactRef, CompiledProcess, DomainError, ProcessDefinition, ProcessVersion,
    Snapshot, canonical, identifier,
)

COMPILER_VERSION = "process-runtime.compiler.v1"
COMPILED_SCHEMA = "process.compiled.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_JSON_DEPTH = 48
MAX_JSON_NODES = 100_000
MAX_TYPE_DEPTH = 16


def _bounded(value: Any) -> None:
    """Reject excessive or non-JSON structures before recursive schema traversal."""
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > MAX_JSON_DEPTH or count > MAX_JSON_NODES:
            raise DomainError("malformed_request", "Process document exceeds structural limits")
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise DomainError("malformed_request", "Process object keys must be strings")
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif item is not None and type(item) not in (str, int, float, bool):
            raise DomainError("malformed_request", "Process document must contain JSON values")
    try:
        size = len(canonical(value).encode("utf-8"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise DomainError("malformed_request", "Process document is not finite UTF-8 JSON") from exc
    if size > MAX_DOCUMENT_BYTES:
        raise DomainError("malformed_request", "Process document exceeds the byte limit")


def _type(spec: dict, depth: int = 0) -> dict:
    if depth > MAX_TYPE_DEPTH:
        raise DomainError("type_mismatch", "Value type exceeds nesting limit")
    kind = spec["kind"]
    if kind == "array":
        return {"kind": kind, "items": _type(spec["items"], depth + 1)}
    if kind == "object":
        properties = spec["properties"]
        for name in properties:
            identifier(name)
        if not set(spec["required"]) <= properties.keys():
            raise DomainError("type_mismatch", "Object requires an undeclared property")
        return {"kind": kind,
                "properties": {name: _type(properties[name], depth + 1) for name in sorted(properties)},
                "required": sorted(spec["required"])}
    return {"kind": kind}


def compatible(source: dict, target: dict) -> bool:
    """Every value admitted by source must be accepted by target (closed objects)."""
    if source["kind"] == "integer" and target["kind"] == "number":
        return True
    if source["kind"] != target["kind"]:
        return False
    if source["kind"] == "array":
        return compatible(source["items"], target["items"])
    if source["kind"] == "object":
        source_properties, target_properties = source["properties"], target["properties"]
        return (set(target["required"]) <= set(source["required"])
                and source_properties.keys() <= target_properties.keys()
                and all(compatible(spec, target_properties[name])
                        for name, spec in source_properties.items()))
    return True


def _matches(value: Any, spec: dict) -> bool:
    kind = spec["kind"]
    if kind == "string":
        return type(value) is str
    if kind == "boolean":
        return type(value) is bool
    if kind == "integer":
        return type(value) is int
    if kind == "number":
        return type(value) is int or (type(value) is float and math.isfinite(value))
    if kind == "array":
        return type(value) is list and all(_matches(item, spec["items"]) for item in value)
    if kind == "object":
        return (type(value) is dict and set(spec["required"]) <= value.keys()
                and value.keys() <= spec["properties"].keys()
                and all(_matches(item, spec["properties"][name]) for name, item in value.items()))
    if kind == "artifact":
        if type(value) is not dict or set(value) != {"content_hash", "byte_length", "media_type"}:
            return False
        try:
            ArtifactRef(**value)
        except (DomainError, TypeError):
            return False
        return True
    return False


def validate_values(values: dict | Snapshot, ports: dict) -> Snapshot:
    """Validate exact run/step port names and values against compiled type specs.

    All top-level ports are required. Object types carry their own required list.
    This checks artifact reference shape, not availability or content integrity.
    """
    raw = values.value if isinstance(values, Snapshot) else values
    _bounded(raw)
    _bounded(ports)
    # Validate type definitions even when this helper is called outside compilation.
    schema = validate({"schema": "process.draft.v1", "process_id": "type-check",
                       "inputs": ports, "steps": [{"step_id": "check", "depends_on": [],
                       "capabilities": [], "resources": [], "inputs": {}, "bindings": {},
                       "outputs": {}, "max_attempts": 1}]}, "process_draft").value
    types = {name: _type(spec) for name, spec in schema["inputs"].items()}
    for name in types:
        identifier(name)
    if type(raw) is not dict or raw.keys() != types.keys() or any(
            not _matches(raw[name], spec) for name, spec in types.items()):
        raise DomainError("type_mismatch", "Values do not match the exact declared ports")
    return Snapshot.of(raw)


def compile_draft(draft: dict | Snapshot) -> CompiledProcess:
    raw = draft.value if isinstance(draft, Snapshot) else draft
    _bounded(raw)
    draft_value = validate(raw, "process_draft").value
    process_id = draft_value["process_id"]
    steps: dict[str, dict] = {}
    for raw_step in draft_value["steps"]:
        step_id = identifier(raw_step["step_id"])
        if step_id in steps:
            raise DomainError("invalid_dag", "Duplicate step identifier")
        if type(raw_step["max_attempts"]) is not int:
            raise DomainError("malformed_request", "max_attempts must be an integer JSON value")
        step = dict(raw_step)
        for field in ("depends_on", "capabilities", "resources"):
            for value in step[field]:
                identifier(value)
            step[field] = sorted(step[field])
        for field in ("inputs", "outputs"):
            for name in step[field]:
                identifier(name)
            step[field] = {name: _type(spec) for name, spec in sorted(step[field].items())}
        if step["inputs"].keys() != step["bindings"].keys():
            raise DomainError("invalid_dag", "Every step input needs exactly one declared binding")
        steps[step_id] = step
    inputs = {name: _type(spec) for name, spec in sorted(draft_value["inputs"].items())}
    for name in inputs:
        identifier(name)
    successors: dict[str, list[str]] = {name: [] for name in steps}
    remaining = {}
    for name, step in steps.items():
        if name in step["depends_on"]:
            raise DomainError("invalid_dag", "A step cannot depend on itself")
        if any(dependency not in steps for dependency in step["depends_on"]):
            raise DomainError("invalid_dag", "Step dependency does not exist")
        remaining[name] = len(step["depends_on"])
        for dependency in step["depends_on"]:
            successors[dependency].append(name)
    roots = sorted(name for name, count in remaining.items() if count == 0)
    ready = list(roots)
    heapq.heapify(ready)
    order: list[str] = []
    ancestors: dict[str, set[str]] = {}
    while ready:
        name = heapq.heappop(ready)
        order.append(name)
        ancestry = set(steps[name]["depends_on"])
        for dependency in steps[name]["depends_on"]:
            ancestry.update(ancestors[dependency])
        ancestors[name] = ancestry
        for successor in sorted(successors[name]):
            remaining[successor] -= 1
            if remaining[successor] == 0:
                heapq.heappush(ready, successor)
    if len(order) != len(steps):
        raise DomainError("invalid_dag", "Process contains a dependency cycle")
    for name, step in steps.items():
        for port, binding in step["bindings"].items():
            expected = step["inputs"][port]
            if binding["source"] == "literal":
                if not _matches(binding["value"], expected):
                    raise DomainError("type_mismatch", "Literal does not match its input type")
                continue
            if binding["source"] == "run_input":
                source = inputs.get(binding["name"])
            else:
                producer = binding["step_id"]
                if producer not in ancestors[name]:
                    raise DomainError("invalid_dag", "Output binding must reference a declared ancestor")
                source = steps[producer]["outputs"].get(binding["name"])
            if source is None:
                raise DomainError("invalid_dag", "Binding references an undeclared source port")
            if not compatible(source, expected):
                raise DomainError("type_mismatch", "Bound source type is incompatible with the input type")
    compiled = {"schema": COMPILED_SCHEMA, "compiler": COMPILER_VERSION,
                "process_id": process_id, "inputs": inputs,
                "steps": [steps[name] for name in sorted(steps)], "roots": roots,
                "topological_order": order,
                "ancestors": {name: sorted(ancestors[name]) for name in sorted(steps)}}
    if "title" in draft_value:
        compiled["title"] = draft_value["title"]
    snapshot = Snapshot.of(compiled)
    return CompiledProcess(process_id, snapshot, snapshot.digest)


@dataclass(frozen=True)
class CompiledSource:
    """Exact immutable source revision/provenance alongside its compiled value."""
    definition: ProcessDefinition
    compiled: CompiledProcess

    @property
    def source_revision(self) -> int:
        return self.definition.revision

    @property
    def source_draft(self) -> Snapshot:
        return self.definition.draft

    @property
    def provenance(self) -> Snapshot:
        return self.definition.provenance


def compile_definition(definition: ProcessDefinition) -> CompiledSource:
    if not isinstance(definition, ProcessDefinition):
        raise DomainError("malformed_request", "Expected an immutable ProcessDefinition")
    _bounded(definition.provenance.value)
    if not Draft202012Validator(PROVENANCE).is_valid(definition.provenance.value):
        raise DomainError("malformed_request", "Source provenance does not conform to v1")
    compiled = compile_draft(definition.draft)
    if compiled.process_id != definition.process_id:
        raise DomainError("invalid_dag", "Definition and draft process identities differ")
    return CompiledSource(definition, compiled)


def publish(definition: ProcessDefinition, *, expected_revision: int, version_id: str,
            ordinal: int, published_at_ms: int) -> ProcessVersion:
    """Build a version value. Caller must CAS the revision and insert atomically.

    No latest-version lookup, clock, ID allocation or persistence occurs here.
    Source provenance is retained separately by CompiledSource/ProcessDefinition.
    """
    if not isinstance(definition, ProcessDefinition) or type(expected_revision) is not int or expected_revision != definition.revision:
        raise DomainError("version_conflict", "Publication requires the exact current draft revision")
    source = compile_definition(definition)
    if source.provenance.value["uncertainties"]:
        raise DomainError("invalid_dag", "Resolve source parser uncertainties before publication")
    return ProcessVersion(version_id, ordinal, source.compiled, source.source_revision, published_at_ms)
