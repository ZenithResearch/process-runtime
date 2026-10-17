"""Deterministic, effect-free fixture execution through the public runtime API.

This module is a local validation tool, never a production executor. Its closed
fixture program can return values or fail; it cannot invoke a callable, import a
handler, dispatch an integration, open an artifact URI, or send an effect.
"""
from __future__ import annotations

import base64
from pathlib import Path
import tempfile

from .application import Runtime
from .authority import LocalDevUntrustedVerifier, local_dev_envelope, resource_for
from .compiler import compile_draft
from .domain import DomainError, Snapshot, identifier, sha256
from .sqlite_store import SQLiteStore

SHADOW_CLOCK_MS = 1_700_000_000_000


def run_shadow(draft: dict | Snapshot, fixture: dict | Snapshot) -> Snapshot:
    """Run one closed synthetic scenario in an isolated temporary database.

    Normalized receipt hashes retain all receipt semantics except randomly
    allocated attempt/receipt IDs, replaced by stable step-and-ordinal aliases.
    No external effects or caller-provided handlers are available.
    """
    draft = draft.value if isinstance(draft, Snapshot) else Snapshot.of(draft).value
    fixture = fixture.value if isinstance(fixture, Snapshot) else Snapshot.of(fixture).value
    compiled = compile_draft(draft)
    if (type(fixture) is not dict or set(fixture) != {"schema", "scenario_id", "inputs", "artifacts", "steps"}
            or fixture["schema"] != "runtime.shadow-fixture.v1"
            or type(fixture["steps"]) is not dict or type(fixture["artifacts"]) is not dict):
        raise DomainError("malformed_request", "Expected a closed shadow fixture")
    scenario = identifier(fixture["scenario_id"])
    specs = {step["step_id"]: step for step in compiled.snapshot.value["steps"]}
    if fixture["steps"].keys() != specs.keys():
        raise DomainError("malformed_request", "Every process step requires one fixture outcome")
    for outcome in fixture["steps"].values():
        if type(outcome) is not dict or not (
                set(outcome) == {"outcome", "outputs"} and outcome["outcome"] == "succeeded"
                or set(outcome) == {"outcome", "reason"} and outcome["outcome"] == "failed"
                   and type(outcome["reason"]) is str and 1 <= len(outcome["reason"]) <= 4096):
            raise DomainError("malformed_request", "Fixture handlers can only return outputs or fail")
    artifact_values, artifact_payloads = {}, []
    for name, artifact in sorted(fixture["artifacts"].items()):
        identifier(name)
        if type(artifact) is not dict or set(artifact) != {"media_type", "content_utf8"} or type(artifact["content_utf8"]) is not str:
            raise DomainError("malformed_request", "Fixture artifacts require explicit retained UTF-8 content")
        content = artifact["content_utf8"].encode("utf-8")
        ref = {"content_hash": sha256(content), "byte_length": len(content), "media_type": artifact["media_type"]}
        artifact_values[name] = ref
        artifact_payloads.append({"artifact": ref, "content_base64": base64.b64encode(content).decode()})

    def materialize(value):
        if type(value) is dict:
            if set(value) == {"$artifact"}:
                if type(value["$artifact"]) is not str or value["$artifact"] not in artifact_values:
                    raise DomainError("malformed_request", "Fixture references an undeclared artifact")
                return artifact_values[value["$artifact"]]
            return {key: materialize(item) for key, item in value.items()}
        if type(value) is list:
            return [materialize(item) for item in value]
        return value

    with tempfile.TemporaryDirectory(prefix="process-runtime-shadow-") as directory:
        store = SQLiteStore(Path(directory) / "runtime.db")
        try:
            runtime = Runtime(store, verifier=LocalDevUntrustedVerifier("shadow-fixture"),
                              environment="test", allow_local_dev_untrusted=True,
                              clock=lambda: SHADOW_CLOCK_MS)
            sequence = 0
            def call(operation, payload, expected_version=None, *, query=False):
                nonlocal sequence
                sequence += 1
                if query:
                    body = {"schema": "runtime.query.v1", "operation": operation, "payload": payload}
                else:
                    # This fixed allowlist excludes every external-effect operation.
                    if operation not in {"artifact.put", "process.draft.put", "process.publish", "actor.register",
                                         "run.create", "executor.claim", "executor.complete", "executor.fail"}:
                        raise DomainError("forbidden", "Shadow execution forbids this operation")
                    body = {"schema": "runtime.command.v1", "operation": operation, "payload": payload,
                            "request_id": f"shadow-request-{sequence}", "expected_version": expected_version,
                            "resource": "pending"}
                    body["resource"] = resource_for(Snapshot.of(body))
                request = Snapshot.of(body)
                proof = local_dev_envelope(request, now_ms=SHADOW_CLOCK_MS,
                    session_id="01" * 16, nonce=f"{sequence:024x}")
                return (runtime.query(body, proof)["data"] if query else runtime.execute(body, proof)["result"])

            for payload in artifact_payloads:
                call("artifact.put", payload)
            provenance = {"source_id": "shadow-retained-resource", "media_type": "application/json",
                "content_hash": Snapshot.of(draft).digest, "parser": "explicit-json-v1", "uncertainties": []}
            call("process.draft.put", {"draft": draft, "provenance": provenance})
            pin = call("process.publish", {"process_id": compiled.process_id, "draft_revision": 1,
                "version_id": "shadow-version-" + compiled.compilation_hash[:48]}, 1)["pin"]
            call("actor.register", {"actor_id": "shadow-worker", "capabilities": sorted({c for s in specs.values() for c in s["capabilities"]}),
                 "resources": sorted({r for s in specs.values() for r in s["resources"]})})
            run_id = "shadow-" + scenario
            call("run.create", {"run_id": run_id, "pin": pin, "inputs": materialize(fixture["inputs"])})
            trace, results, failures = [], [], []
            for round_index in range(len(specs) + 1):
                work, after = [], None
                while True:
                    payload = {"actor_id": "shadow-worker", "limit": 100}
                    if after is not None: payload["after"] = after
                    page = call("work.list", payload, query=True)
                    work.extend(page["work"])
                    if page["next_cursor"] is None: break
                    after = page["next_cursor"]
                work.sort(key=lambda item: item["step_id"])
                trace.append({"round": round_index, "runnable": [item["step_id"] for item in work]})
                if not work:
                    break
                claims = [call("executor.claim", {"run_id": run_id, "step_id": item["step_id"], "actor_id": "shadow-worker", "lease_ms": 1000}, item["version"]) for item in work]
                for claim in claims:
                    step_id = claim["step_id"]
                    binding = {key: claim[key] for key in ("run_id", "step_id", "attempt_id", "fence")}
                    outcome = fixture["steps"][step_id]
                    if outcome["outcome"] == "succeeded":
                        completed = call("executor.complete", {**binding, "outputs": materialize(outcome["outputs"])}, claim["step_version"])
                        output = call("output.get", {key: claim[key] for key in ("run_id", "step_id", "attempt_id")}, query=True)
                        output_digest = output["output_digest"]
                    else:
                        completed = call("executor.fail", {**binding, "reason": outcome["reason"], "retryable": False}, claim["step_version"])
                        output_digest = None
                        failures.append({"step_id": step_id, "reason": outcome["reason"], "retryable": False})
                    receipt = call("receipt.get", {"receipt_id": completed["receipt_id"]}, query=True)
                    attempt = call("attempt.get", {key: claim[key] for key in ("run_id", "step_id", "attempt_id")}, query=True)
                    alias = f"shadow-attempt-{step_id}-{attempt['ordinal']}"
                    receipt["attempt_id"] = alias
                    receipt["receipt_id"] = "receipt-" + alias
                    results.append({"step_id": step_id, "outcome": outcome["outcome"],
                        "input_digest": claim["input_digest"], "output_digest": output_digest,
                        "receipt": receipt, "receipt_digest": Snapshot.of(receipt).digest})
            else:
                raise DomainError("invalid_dag", "Shadow execution failed to reach a bounded terminal point")
            run = call("run.get", {"run_id": run_id}, query=True)
            return Snapshot.of({"schema": "runtime.shadow-report.v1", "scenario_id": scenario,
                "authority_mode": "local_dev_untrusted", "external_effects": "forbidden",
                "process_id": compiled.process_id, "compilation_hash": compiled.compilation_hash,
                "runnable_trace": trace, "steps": results, "failures": failures,
                "run_state": run["state"], "final_step_states": {s["step_id"]: s["state"] for s in run["steps"]}})
        finally:
            store.close()


def compare_shadow(actual: Snapshot, expected: Snapshot) -> Snapshot:
    """Retain and classify every field-level divergence; never rewrite goldens."""
    if not isinstance(actual, Snapshot) or not isinstance(expected, Snapshot):
        raise DomainError("malformed_request", "Comparison requires immutable reports")
    differences = []
    def category(path):
        if path and path[0] == "runnable_trace": return "runnable"
        if path and path[0] == "failures": return "failure"
        if path and path[0] in ("run_state", "final_step_states"): return "terminal-state"
        if path and path[0] == "compilation_hash": return "compilation"
        if path and path[0] == "steps":
            if any(str(part).startswith("receipt") for part in path): return "receipt"
            if "input_digest" in path: return "input"
            if "output_digest" in path: return "output"
            return "execution"
        return "report-contract"
    def visit(left, right, path):
        if type(left) is dict and type(right) is dict:
            for key in sorted(left.keys() | right.keys()):
                if key not in left or key not in right:
                    differences.append({"path": path + [key], "category": category(path + [key]),
                        "actual_present": key in left, "expected_present": key in right})
                else: visit(left[key], right[key], path + [key])
        elif type(left) is list and type(right) is list and len(left) == len(right):
            for index, (a, b) in enumerate(zip(left, right)): visit(a, b, path + [index])
        elif type(left) is not type(right) or left != right:
            differences.append({"path": path, "category": category(path), "actual": left, "expected": right})
    visit(actual.value, expected.value, [])
    return Snapshot.of({"schema": "runtime.shadow-comparison.v1", "matches": not differences,
                        "actual_digest": actual.digest, "expected_digest": expected.digest, "divergences": differences})
