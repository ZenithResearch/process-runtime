"""Transactional runtime use cases; no transport or concrete storage dependency."""
from __future__ import annotations

import base64
from contextlib import ExitStack
from dataclasses import asdict
import time
import uuid
from typing import Callable

from .compiler import publish, validate_values
from .contracts import validate
from .domain import (Actor, ArtifactRef, Attempt, AttemptState, DomainError, Lease,
                     OutputCommit, ProcessDefinition, ProcessPin, Receipt, RunState,
                     Snapshot, StepState, sha256, transition)
from .ports import Record, RecordKind as K, RequestResult, RuntimeStore


class _AdmissionClosed(DomainError):
    retryable = True


def stable_id(prefix: str, value: dict) -> str:
    return prefix + Snapshot.of(value).digest[:48]


def step_key(run_id: str, step_id: str) -> str:
    return stable_id("step-", {"run_id": run_id, "step_id": step_id})


def load(tx, kind, identifier):
    record = tx.get(kind, identifier)
    if record is None:
        raise DomainError("not_found", "The requested runtime record does not exist")
    return record


def insert(tx, kind, identifier, value):
    record = Record(kind, identifier, 1, Snapshot.of({**value, "version": 1}))
    tx.insert(record)
    return record


def update(tx, record, **changes):
    value = {**record.value.value, **changes, "version": record.version + 1}
    new = Record(record.kind, record.record_id, record.version + 1, Snapshot.of(value))
    tx.replace(new, expected_version=record.version)
    return new


def expect(record, version):
    if record.version != version:
        raise DomainError("version_conflict", "The supplied version is no longer current")


def records(tx, kind):
    after = None
    while True:
        page = tx.scan(kind, after=after, limit=1000)
        yield from page
        if len(page) < 1000:
            return
        after = page[-1].record_id


class Runtime:
    def __init__(self, store: RuntimeStore, *, verifier=None, environment="production",
                 allow_local_dev_untrusted=False, clock: Callable[[], int] | None = None,
                 wakeups=None, audience="runtime://receiver-local", new_run_admission=None):
        from .authority import DenyAllVerifier
        if environment not in ("production", "development", "test"):
            raise ValueError("Unknown runtime environment")
        if environment == "production" and allow_local_dev_untrusted:
            raise ValueError("local_dev_untrusted is prohibited in production")
        self.store, self.verifier = store, verifier or DenyAllVerifier()
        self.allow_local_dev = allow_local_dev_untrusted
        self.clock = clock or (lambda: time.time_ns() // 1_000_000)
        self.wakeups, self.audience = wakeups, audience
        from .admission import StaticAdmissionGate
        self.new_run_admission = new_run_admission or StaticAdmissionGate(environment != "production")

    def _authority(self, snapshot, evidence, now):
        from .authority import resource_for, authorize_binding
        verified = self.verifier.verify(envelope=evidence or b"", command=snapshot, now_ms=now)
        command = snapshot.value
        authorize_binding(verified, snapshot, now_ms=now, allow_local_dev=self.allow_local_dev, expected_audience=self.audience)
        if verified.mode == "local_dev_untrusted":
            if not self.allow_local_dev:
                raise DomainError("unauthenticated", "Local development authority is disabled")
        elif verified.mode != "production_verified":
            raise DomainError("unauthenticated", "Unsupported authority mode")
        if (verified.audience != self.audience or verified.operation != command["operation"]
                or verified.resource != resource_for(snapshot) or verified.request_digest != snapshot.digest
                or not verified.issued_at_ms <= now < verified.expires_at_ms
                or not verified.subject_id or not verified.key_id or not verified.session_id or not verified.nonce):
            raise DomainError("forbidden", "Verified authority does not match the exact request")
        if command["schema"] == "runtime.command.v1" and command["resource"] != verified.resource:
            raise DomainError("forbidden", "Command resource differs from its payload")
        return verified

    def execute(self, command: dict, evidence: bytes | None = None) -> dict:
        snapshot = validate(command, "command")
        command = snapshot.value
        with ExitStack() as scope:
            admission_allowed = scope.enter_context(self.new_run_admission.hold()) if command['operation'] in ('run.create', 'handoff.consume') else True
            tx = scope.enter_context(self.store.transaction())
            now = self.clock()
            authority = self._authority(snapshot, evidence, now)
            now = self.clock()
            from .authority import authorize_binding
            authorize_binding(authority, snapshot, now_ms=now, allow_local_dev=self.allow_local_dev, expected_audience=self.audience)
            prior = tx.request_result(authority.subject_id, command["request_id"])
            if prior:
                if prior.request_digest != snapshot.digest:
                    raise DomainError("idempotency_conflict", "Request identity was used for different content")
                return {**prior.response.value, "duplicate": True}
            tx.admit_replay(subject_id=authority.subject_id, session_id=authority.session_id,
                            opcode=authority.opcode, nonce=authority.nonce, expires_at_ms=authority.expires_at_ms)
            result, version, event_kind = self._execute(tx, snapshot.value, authority, now, admission_allowed)
            result = self._execution_summary(tx, result)
            response = {"schema": "runtime.result.v1", "request_id": command["request_id"],
                        "operation": command["operation"], "duplicate": False, "resource": command["resource"],
                        "version": version, "result": result}
            validate(response, "result")
            self._event(tx, event_kind, command, version, now, result, authority.mode)
            tx.record_result(RequestResult(authority.subject_id, command["request_id"], snapshot.digest, Snapshot.of(response)))
        if self.wakeups:
            try:
                self.flush_wakeups()
            except Exception:
                # Hints have no effect on committed execution state or API success.
                pass
        return response

    @staticmethod
    def _execution_summary(tx, data):
        data = dict(data)
        run = tx.get(K.PROCESS_RUN, data["run_id"]) if "run_id" in data else None
        if run:
            data.update(run_state=run.value.value["state"], run_version=run.version)
            step = tx.get(K.STEP_RUN, step_key(data["run_id"], data["step_id"])) if "step_id" in data else None
            if step:
                data.update(step_state=step.value.value["state"], step_version=step.version)
        return data

    @staticmethod
    def _event(tx, kind, command, version, now, data, mode):
        data = Runtime._execution_summary(tx, data)
        event_id = str(uuid.uuid4())
        allowed = {"run_id", "run_version", "run_state", "step_state", "state", "pin", "step_id", "step_version", "attempt_id",
                   "actor_id", "output_id", "output_digest", "receipt_id", "effect_id", "fence",
                   "lease_expires_at_ms", "process_id", "source_event_id", "ordinal", "source_revision"}
        summary = {key: value for key, value in data.items() if key in allowed}
        sequence = tx.append_event(Snapshot.of({"schema": "runtime.event.v1", "event_id": event_id,
            "sequence": 1, "kind": kind, "resource": command["resource"], "resource_version": version,
            "request_id": command["request_id"], "correlation_id": data.get("run_id", command["request_id"]),
            "recorded_at_ms": now, "data": {**summary, "authority_mode": mode}}))
        insert(tx, K.OUTBOX, event_id, {"event_id": event_id, "sequence": sequence, "state": "pending"})
        return sequence

    def flush_wakeups(self, limit: int = 100) -> int:
        """At-least-once hints; consumers always query canonical state by cursor."""
        if self.wakeups is None:
            return 0
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise DomainError("malformed_request", "Invalid outbox page size")
        with self.store.transaction() as tx:
            pending = [record for record in records(tx, K.OUTBOX) if record.value.value["state"] == "pending"][:limit]
        delivered = 0
        for record in pending:
            self.wakeups.notify(record.value.value["sequence"])
            with self.store.transaction() as tx:
                current = load(tx, K.OUTBOX, record.record_id)
                if current.value.value["state"] == "pending":
                    update(tx, current, state="delivered")
            delivered += 1
        return delivered

    def _execute(self, tx, command, authority, now, admission_allowed=True):
        op, p, expected = command["operation"], command["payload"], command["expected_version"]
        if op == "process.draft.put":
            process_id = p["draft"]["process_id"]
            old = tx.get(K.PROCESS_DEFINITION, process_id)
            if old is None:
                if expected is not None:
                    raise DomainError("version_conflict", "A new draft requires an empty precondition")
                record = insert(tx, K.PROCESS_DEFINITION, process_id, {"process_id": process_id,
                    "revision": 1, "draft": p["draft"], "provenance": p["provenance"], "last_ordinal": 0, "active_version": None})
            else:
                expect(old, expected)
                record = update(tx, old, revision=old.value.value["revision"] + 1,
                                draft=p["draft"], provenance=p["provenance"])
            return record.value.value, record.version, "process.draft_updated"
        if op == "process.publish":
            source = load(tx, K.PROCESS_DEFINITION, p["process_id"])
            expect(source, expected)
            raw = source.value.value
            definition = ProcessDefinition(p["process_id"], raw["revision"], Snapshot.of(raw["draft"]), Snapshot.of(raw["provenance"]))
            version = publish(definition, expected_revision=p["draft_revision"], version_id=p["version_id"],
                              ordinal=raw["last_ordinal"] + 1, published_at_ms=now)
            data = {"pin": asdict(ProcessPin.of(version)), "ordinal": version.ordinal,
                    "source_revision": version.source_revision, "published_at_ms": now,
                    "compiled": version.compiled.snapshot.value, "source_draft": raw["draft"], "provenance": raw["provenance"]}
            insert(tx, K.PROCESS_VERSION, version.version_id, data)
            updated = update(tx, source, last_ordinal=version.ordinal, active_version=data["pin"])
            return data, updated.version, "process.published"
        if op == "run.create":
            if expected is not None:
                raise DomainError("version_conflict", "New runs require an empty precondition")
            record = self._create_run(tx, p["run_id"], p["pin"], p["inputs"], now, p.get("source_ref"), admission_allowed=admission_allowed)
            return record.value.value, 1, "run.created"
        if op == "handoff.consume":
            if expected is not None:
                raise DomainError("version_conflict", "New handoffs require an empty precondition")
            key = stable_id("inbox-", {"source": p["source"], "event_id": p["event_id"]})
            digest = Snapshot.of(p).digest
            prior = tx.get(K.INBOX, key)
            if prior:
                if prior.value.value["digest"] != digest:
                    raise DomainError("idempotency_conflict", "Source event content changed")
                run = load(tx, K.PROCESS_RUN, prior.value.value["run_id"])
                return {"run_id": run.record_id, "pin": p["pin"], "state": run.value.value["state"], "source_event_id": p["event_id"]}, run.version, "handoff.accepted"
            for inbox in records(tx, K.INBOX):
                value = inbox.value.value
                if value["source"] == p["source"] and value["idempotency_key"] == p["idempotency_key"]:
                    raise DomainError("idempotency_conflict", "Source idempotency identity was already consumed")
            run_id = stable_id("handoff-", {"source": p["source"], "event_id": p["event_id"]})
            run = self._create_run(tx, run_id, p["pin"], p["inputs"], now, f"handoff:{key}", admission_allowed=admission_allowed)
            insert(tx, K.INBOX, key, {"source": p["source"], "event_id": p["event_id"], "idempotency_key": p["idempotency_key"],
                                    "digest": digest, "run_id": run_id, "event": p, "consumed_at_ms": now})
            return {"run_id": run_id, "pin": p["pin"], "state": run.value.value["state"], "source_event_id": p["event_id"]}, 1, "handoff.accepted"
        if op in ("actor.register", "actor.advertise"):
            Actor(p["actor_id"], tuple(p["capabilities"]), tuple(p["resources"]), p.get("directory_ref"))
            old = tx.get(K.ACTOR, p["actor_id"])
            if op == "actor.register":
                if expected is not None:
                    raise DomainError("version_conflict", "New actors require an empty precondition")
                record = insert(tx, K.ACTOR, p["actor_id"], {**p, "subject_id": authority.subject_id})
            else:
                old = load(tx, K.ACTOR, p["actor_id"])
                expect(old, expected)
                self._actor_owner(old, authority)
                record = update(tx, old, capabilities=p["capabilities"], resources=p["resources"])
            return record.value.value, record.version, "actor.registered" if op == "actor.register" else "actor.advertised"
        if op == "artifact.put":
            if expected is not None:
                raise DomainError("version_conflict", "Content-addressed artifacts use an empty precondition")
            try:
                content = base64.b64decode(p["content_base64"], validate=True)
            except (ValueError, TypeError) as exc:
                raise DomainError("malformed_request", "Artifact bytes are not valid base64") from exc
            ref = ArtifactRef(**p["artifact"])
            ref.verify(content)
            prior = tx.get(K.ARTIFACT, ref.content_hash)
            data = {"artifact": p["artifact"], "content_base64": p["content_base64"]}
            if prior and {k: v for k, v in prior.value.value.items() if k != "version"} != data:
                raise DomainError("idempotency_conflict", "Artifact identity has conflicting metadata")
            if not prior:
                insert(tx, K.ARTIFACT, ref.content_hash, data)
            return {"artifact": p["artifact"]}, 1, "artifact.committed"
        if op in ("run.cancel", "run.retry"):
            return self._run_control(tx, command, now)
        if op == "effect.resolve":
            effect = load(tx, K.EFFECT, p["effect_id"])
            expect(effect, expected)
            if effect.value.value["state"] not in ("dispatched", "acknowledged", "unknown"):
                raise DomainError("not_ready", "Only unresolved dispatched effects can be reconciled")
            updated = update(tx, effect, state=p["outcome"], provider_reference=p["provider_reference"],
                             observation_digest=p["observation_digest"], resolution_reason=p["reason"], resolved_by=authority.subject_id, resolved_at_ms=now)
            return updated.value.value, updated.version, "effect.resolved"
        if op.startswith("executor."):
            return self._executor(tx, command, authority, now)
        raise DomainError("unsupported_contract", "Unsupported runtime operation")

    def _version(self, tx, pin):
        version = load(tx, K.PROCESS_VERSION, pin["process_version"])
        data = version.value.value
        if data["pin"] != pin or Snapshot.of(data["compiled"]).digest != pin["compilation_hash"]:
            raise DomainError("incompatible_version", "The exact published version and compilation hash are required")
        return data

    def _create_run(self, tx, run_id, pin, inputs, now, source_ref=None, *, admission_allowed=True):
        if not admission_allowed:
            raise _AdmissionClosed("not_ready", "New run admission is closed")
        compiled = self._version(tx, pin)["compiled"]
        values = validate_values(inputs, compiled["inputs"])
        self._artifacts(tx, values.value, compiled["inputs"])
        record = insert(tx, K.PROCESS_RUN, run_id, {"run_id": run_id, "pin": pin, "inputs": values.value,
                         "state": "pending", "source_ref": source_ref, "created_at_ms": now})
        for step in compiled["steps"]:
            insert(tx, K.STEP_RUN, step_key(run_id, step["step_id"]), {"run_id": run_id,
                   "step_id": step["step_id"], "state": "ready" if not step["depends_on"] else "waiting",
                   "attempt_id": None, "fence": 0, "attempt_count": 0})
        return record

    @staticmethod
    def _artifacts(tx, values, ports):
        def check(value, spec):
            if spec["kind"] == "artifact":
                stored = load(tx, K.ARTIFACT, value["content_hash"]).value.value
                if stored["artifact"] != value:
                    raise DomainError("type_mismatch", "Artifact reference does not match stored content")
            elif spec["kind"] == "array":
                for item in value:
                    check(item, spec["items"])
            elif spec["kind"] == "object":
                for name, item in value.items():
                    check(item, spec["properties"][name])
        for name, value in values.items():
            check(value, ports[name])

    @staticmethod
    def _actor_owner(actor, authority):
        if actor.value.value["subject_id"] != authority.subject_id:
            raise DomainError("forbidden", "Actor registration belongs to a different authenticated subject")

    def _run_parts(self, tx, run_id):
        run = load(tx, K.PROCESS_RUN, run_id)
        compiled = self._version(tx, run.value.value["pin"])["compiled"]
        steps = {s["step_id"]: load(tx, K.STEP_RUN, step_key(run_id, s["step_id"])) for s in compiled["steps"]}
        return run, {s["step_id"]: s for s in compiled["steps"]}, steps

    @staticmethod
    def _move_run(tx, run, target):
        if run.value.value["state"] == target:
            return run
        transition(RunState(run.value.value["state"]), RunState(target))
        return update(tx, run, state=target)

    @staticmethod
    def _move_step(tx, step, target, **updates):
        if step.value.value["state"] != target:
            transition(StepState(step.value.value["state"]), StepState(target))
        return update(tx, step, state=target, **updates)

    def _executor(self, tx, command, authority, now):
        op, p = command["operation"], command["payload"]
        run, specs, steps = self._run_parts(tx, p["run_id"])
        if p["step_id"] not in steps:
            raise DomainError("not_found", "Step is absent from the pinned process")
        step, spec = steps[p["step_id"]], specs[p["step_id"]]
        expect(step, command["expected_version"])
        if run.value.value["state"] not in ("pending", "running", "blocked"):
            raise DomainError("not_ready", "The process run is terminal")
        if op == "executor.claim":
            actor = load(tx, K.ACTOR, p["actor_id"])
            self._actor_owner(actor, authority)
            value = actor.value.value
            worker = Actor(p["actor_id"], tuple(value["capabilities"]), tuple(value["resources"]), value.get("directory_ref"))
            if worker.missing(tuple(spec["capabilities"]), tuple(spec["resources"])):
                raise DomainError("capability_mismatch", "Actor lacks required capabilities or resources")
            if any(s.value.value["state"] == "failed" for s in steps.values()):
                raise DomainError("not_ready", "A failed branch blocks new claims")
            if step.value.value["state"] != "ready" or any(steps[name].value.value["state"] != "succeeded" for name in spec["depends_on"]):
                raise DomainError("not_ready", "Step dependencies are not all committed")
            count = step.value.value["attempt_count"] + 1
            if count > spec["max_attempts"]:
                raise DomainError("not_ready", "Step attempt budget is exhausted")
            inputs = {}
            for name, binding in spec["bindings"].items():
                if binding["source"] == "literal":
                    inputs[name] = binding["value"]
                elif binding["source"] == "run_input":
                    inputs[name] = run.value.value["inputs"][binding["name"]]
                else:
                    producer = steps[binding["step_id"]].value.value
                    output = load(tx, K.OUTPUT_COMMIT, "output-" + producer["attempt_id"])
                    inputs[name] = output.value.value["outputs"][binding["name"]]
            values = validate_values(inputs, spec["inputs"])
            attempt_id, fence = str(uuid.uuid4()), step.value.value["fence"] + 1
            attempt = Attempt(attempt_id, run.record_id, p["step_id"], count, p["actor_id"], values.digest, fence, now)
            insert(tx, K.ATTEMPT, attempt_id, {**asdict(attempt), "state": attempt.state.value, "inputs": values.value})
            lease = Lease(run.record_id, p["step_id"], attempt_id, p["actor_id"], fence, now + p["lease_ms"])
            insert(tx, K.LEASE, attempt_id, asdict(lease))
            updated = self._move_step(tx, step, "running", attempt_id=attempt_id, fence=fence, attempt_count=count)
            if run.value.value["state"] == "pending":
                run = self._move_run(tx, run, "running")
            return {"run_id": run.record_id, "pin": run.value.value["pin"], "step_id": p["step_id"],
                    "attempt_id": attempt_id, "fence": fence, "actor_id": p["actor_id"], "inputs": inputs,
                    "input_digest": values.digest, "input_types": spec["inputs"], "output_types": spec["outputs"],
                    "lease_expires_at_ms": lease.expires_at_ms, "step_version": updated.version,
                    "run_version": run.version}, updated.version, "attempt.claimed"
        attempt_record, attempt, lease_record = self._current(tx, step, p, authority, now)
        if op == "executor.heartbeat":
            expires = now + p["lease_ms"]
            update(tx, lease_record, expires_at_ms=expires)
            updated = update(tx, step)
            return {"run_id": run.record_id, "attempt_id": attempt.attempt_id, "fence": attempt.fence,
                    "lease_expires_at_ms": expires, "step_version": updated.version}, updated.version, "attempt.heartbeat"
        if op.startswith("executor.effect."):
            return self._effect(tx, command, step, attempt, now)
        if op == "executor.complete":
            effects = self._effects(tx, attempt.attempt_id)
            if any(e.value.value["state"] != "succeeded" for e in effects):
                raise DomainError("unknown_outcome", "Every external effect requires a reconciled successful outcome")
            outputs = validate_values(p["outputs"], spec["outputs"])
            self._artifacts(tx, outputs.value, spec["outputs"])
            output_id = "output-" + attempt.attempt_id
            commit = OutputCommit(output_id, run.record_id, attempt.step_id, attempt.attempt_id, attempt.fence, outputs, outputs.digest, now)
            commit.require_attempt(attempt)
            receipt_id = "receipt-" + attempt.attempt_id
            insert(tx, K.OUTPUT_COMMIT, output_id, {"output_id": output_id, "run_id": run.record_id,
                   "step_id": attempt.step_id, "attempt_id": attempt.attempt_id, "fence": attempt.fence,
                   "pin": run.value.value["pin"], "actor_id": attempt.actor_id, "inputs_digest": attempt.input_digest,
                   "outputs": outputs.value, "output_types": spec["outputs"], "output_digest": outputs.digest,
                   "committed_at_ms": now, "receipt_id": receipt_id})
            self._event(tx, "output.committed", command, step.version + 1, now, {"run_id": run.record_id, "step_id": attempt.step_id, "attempt_id": attempt.attempt_id, "output_id": output_id, "output_digest": outputs.digest}, authority.mode)
            update(tx, attempt_record, state=attempt.move(AttemptState.SUCCEEDED).state.value)
            updated = self._move_step(tx, step, "succeeded")
            self._receipt(tx, run, attempt, "succeeded", now, outputs.digest)
            run = self._refresh(tx, run, specs)
            return {"run_id": run.record_id, "state": run.value.value["state"], "run_version": run.version, "step_id": attempt.step_id, "attempt_id": attempt.attempt_id,
                    "output_id": output_id, "output_digest": outputs.digest, "receipt_id": receipt_id,
                    "step_version": updated.version}, updated.version, "attempt.completed"
        outcome = "released" if op == "executor.release" else "failed"
        if op not in ("executor.release", "executor.fail"):
            raise DomainError("unsupported_contract", "Unknown executor operation")
        update(tx, attempt_record, state=attempt.move(AttemptState(outcome)).state.value, reason=p["reason"])
        safe = self._safe_retry(tx, attempt.attempt_id)
        retryable = op == "executor.release" or p["retryable"]
        if safe and retryable and step.value.value["attempt_count"] < spec["max_attempts"]:
            state = "ready" if op == "executor.release" else "blocked"
        else:
            state = "blocked" if not safe else "failed"
        updated = self._move_step(tx, step, state)
        self._receipt(tx, run, attempt, outcome, now)
        self._refresh(tx, run, specs)
        return {"run_id": run.record_id, "step_id": attempt.step_id, "attempt_id": attempt.attempt_id,
                "state": state, "receipt_id": "receipt-" + attempt.attempt_id}, updated.version, "attempt." + outcome

    def _current(self, tx, step, p, authority, now):
        value = step.value.value
        if value["attempt_id"] != p["attempt_id"] or value["fence"] != p["fence"]:
            raise DomainError("stale_fence", "Attempt is no longer the current fenced claim")
        record = load(tx, K.ATTEMPT, p["attempt_id"])
        raw = record.value.value
        attempt = Attempt(**{k: raw[k] for k in ("attempt_id", "run_id", "step_id", "ordinal", "actor_id", "input_digest", "fence", "started_at_ms")}, state=AttemptState(raw["state"]))
        self._actor_owner(load(tx, K.ACTOR, attempt.actor_id), authority)
        lease_record = load(tx, K.LEASE, attempt.attempt_id)
        lease = Lease(**{k: v for k, v in lease_record.value.value.items() if k != "version"})
        lease.require_current(attempt, now_ms=now, current_fence=value["fence"])
        return record, attempt, lease_record

    @staticmethod
    def _effects(tx, attempt_id):
        return [record for record in records(tx, K.EFFECT) if record.value.value["attempt_id"] == attempt_id]

    def _safe_retry(self, tx, attempt_id):
        return all(effect.value.value["state"] in ("intent", "failed") for effect in self._effects(tx, attempt_id))

    def _effect(self, tx, command, step, attempt, now):
        op, p = command["operation"], command["payload"]
        if op == "executor.effect.intent":
            effect_id = stable_id("effect-", {"attempt_id": attempt.attempt_id, "effect_name": p["effect_name"]})
            value = {"effect_id": effect_id, "run_id": attempt.run_id, "step_id": attempt.step_id,
                     "attempt_id": attempt.attempt_id, "fence": attempt.fence, "effect_name": p["effect_name"],
                     "integration": p["integration"], "request_digest": p["request_digest"],
                     "provider_idempotent": p["provider_idempotent"], "idempotency_key": effect_id,
                     "state": "intent", "created_at_ms": now}
            prior = tx.get(K.EFFECT, effect_id)
            if prior:
                old = prior.value.value
                if any(old[key] != value[key] for key in ("integration", "request_digest", "provider_idempotent")):
                    raise DomainError("idempotency_conflict", "Effect name already binds different intent")
                effect = prior
            else:
                effect = insert(tx, K.EFFECT, effect_id, value)
            event = "effect.intent"
        else:
            effect = load(tx, K.EFFECT, p["effect_id"])
            raw = effect.value.value
            if (raw["attempt_id"], raw["fence"], raw["run_id"], raw["step_id"]) != (attempt.attempt_id, attempt.fence, attempt.run_id, attempt.step_id):
                raise DomainError("stale_fence", "Effect belongs to another execution attempt")
            if op == "executor.effect.dispatch":
                if raw["state"] != "intent":
                    raise DomainError("unknown_outcome", "Effect already dispatched; reconcile before another send")
                effect = update(tx, effect, state="dispatched", dispatched_at_ms=now)
                event = "effect.dispatched"
            else:
                if raw["state"] not in ("dispatched", "acknowledged", "unknown"):
                    raise DomainError("not_ready", "Effect has no unresolved dispatch")
                effect = update(tx, effect, state=p["outcome"], provider_reference=p["provider_reference"],
                                observation_digest=p["observation_digest"], observed_at_ms=now)
                event = "effect.observed"
        updated = update(tx, step)
        return {**effect.value.value, "step_version": updated.version}, updated.version, event

    @staticmethod
    def _receipt(tx, run, attempt, outcome, now, output_digest=None):
        receipt = Receipt("receipt-" + attempt.attempt_id, ProcessPin(**run.value.value["pin"]),
                          attempt.run_id, attempt.step_id, attempt.attempt_id, attempt.actor_id,
                          attempt.input_digest, output_digest, attempt.fence, attempt.started_at_ms,
                          now, AttemptState(outcome))
        value = {**asdict(receipt), "schema": "runtime.receipt.v1", "outcome": outcome}
        validate(value, "receipt")
        insert(tx, K.RECEIPT, receipt.receipt_id, value)

    def _refresh(self, tx, run, specs):
        steps = {name: load(tx, K.STEP_RUN, step_key(run.record_id, name)) for name in specs}
        for name, step in list(steps.items()):
            if step.value.value["state"] == "waiting" and all(steps[dependency].value.value["state"] == "succeeded" for dependency in specs[name]["depends_on"]):
                steps[name] = self._move_step(tx, step, "ready")
        states = [step.value.value["state"] for step in steps.values()]
        target = "succeeded" if all(s == "succeeded" for s in states) else "failed" if "failed" in states and "running" not in states else "blocked" if "blocked" in states or "failed" in states else "running"
        return self._move_run(tx, load(tx, K.PROCESS_RUN, run.record_id), target)

    def _run_control(self, tx, command, now):
        p = command["payload"]
        run, specs, steps = self._run_parts(tx, p["run_id"])
        expect(run, command["expected_version"])
        if command["operation"] == "run.cancel":
            run = self._move_run(tx, run, "cancelled")
            for step in steps.values():
                raw = step.value.value
                if raw["state"] in ("waiting", "ready", "running", "blocked"):
                    if raw["state"] == "running":
                        record = load(tx, K.ATTEMPT, raw["attempt_id"])
                        attempt = self._attempt(record)
                        update(tx, record, state=attempt.move(AttemptState.CANCELLED).state.value)
                        self._unknown_effects(tx, attempt.attempt_id, now)
                        self._receipt(tx, run, attempt, "cancelled", now)
                    self._move_step(tx, step, "cancelled")
            return run.value.value, run.version, "run.cancelled"
        if p["step_id"] not in steps:
            raise DomainError("not_found", "Step is absent from the pinned process")
        step = steps[p["step_id"]]
        raw = step.value.value
        if run.value.value["state"] != "blocked" or raw["state"] != "blocked" or not raw["attempt_id"]:
            raise DomainError("not_ready", "Only a blocked retryable step can request a new Attempt")
        if raw["attempt_count"] >= specs[p["step_id"]]["max_attempts"]:
            raise DomainError("not_ready", "Attempt budget is exhausted")
        if not self._safe_retry(tx, raw["attempt_id"]):
            raise DomainError("unknown_outcome", "Prior effects require explicit reconciliation; completed effects cannot be implicitly repeated")
        self._move_step(tx, step, "ready")
        run = self._refresh(tx, run, specs)
        return {"run_id": run.record_id, "step_id": p["step_id"], "state": run.value.value["state"], "reason": p["reason"]}, run.version, "run.retried"

    @staticmethod
    def _attempt(record):
        raw = record.value.value
        return Attempt(**{key: raw[key] for key in ("attempt_id", "run_id", "step_id", "ordinal", "actor_id", "input_digest", "fence", "started_at_ms")}, state=AttemptState(raw["state"]))

    def _unknown_effects(self, tx, attempt_id, now):
        for effect in self._effects(tx, attempt_id):
            if effect.value.value["state"] in ("dispatched", "acknowledged"):
                update(tx, effect, state="unknown", observed_at_ms=now)

    def recover(self) -> int:
        """Owner maintenance path, not an unauthenticated network operation."""
        count = 0
        with self.store.transaction() as tx:
            now = self.clock()
            for lease_record in list(records(tx, K.LEASE)):
                raw = lease_record.value.value
                attempt_record = load(tx, K.ATTEMPT, raw["attempt_id"])
                if attempt_record.value.value["state"] != "active" or raw["expires_at_ms"] > now:
                    continue
                attempt = self._attempt(attempt_record)
                run, specs, steps = self._run_parts(tx, attempt.run_id)
                step = steps[attempt.step_id]
                update(tx, attempt_record, state=attempt.move(AttemptState.EXPIRED).state.value)
                self._unknown_effects(tx, attempt.attempt_id, now)
                safe = self._safe_retry(tx, attempt.attempt_id)
                state = "ready" if safe and step.value.value["attempt_count"] < specs[attempt.step_id]["max_attempts"] else "failed" if safe else "blocked"
                updated = self._move_step(tx, step, state)
                self._receipt(tx, run, attempt, "expired", now)
                self._refresh(tx, run, specs)
                self._event(tx, "attempt.expired", {"resource": f"runs/{run.record_id}/steps/{attempt.step_id}", "request_id": "recovery-" + attempt.attempt_id}, updated.version, now, {"run_id": run.record_id, "step_id": attempt.step_id, "attempt_id": attempt.attempt_id, "state": state}, "runtime_maintenance")
                count += 1
        return count

    def query(self, query: dict, evidence: bytes | None = None) -> dict:
        snapshot = validate(query, "query")
        query = snapshot.value
        op, p = query["operation"], query["payload"]
        with self.store.transaction() as tx:
            authority = self._authority(snapshot, evidence, self.clock())
            from .authority import authorize_binding
            authorize_binding(authority, snapshot, now_ms=self.clock(), allow_local_dev=self.allow_local_dev, expected_audience=self.audience)
            tx.admit_replay(subject_id=authority.subject_id, session_id=authority.session_id, opcode=authority.opcode, nonce=authority.nonce, expires_at_ms=authority.expires_at_ms)
            simple = {"process.get": (K.PROCESS_DEFINITION, p.get("process_id")),
                      "version.get": (K.PROCESS_VERSION, p.get("process_version")),
                      "artifact.get": (K.ARTIFACT, p.get("content_hash")),
                      "receipt.get": (K.RECEIPT, p.get("receipt_id")), "effect.get": (K.EFFECT, p.get("effect_id"))}
            if op in simple:
                data = load(tx, *simple[op]).value.value
                if op == "receipt.get":
                    data.pop("version", None)
            elif op == "attempt.get":
                attempt = load(tx, K.ATTEMPT, p["attempt_id"])
                raw = attempt.value.value
                if (raw["run_id"], raw["step_id"]) != (p["run_id"], p["step_id"]):
                    raise DomainError("not_found", "Attempt does not belong to this run and step")
                run, specs, steps = self._run_parts(tx, p["run_id"])
                step = steps[p["step_id"]].value.value
                lease = load(tx, K.LEASE, p["attempt_id"]).value.value
                data = {**raw, "pin": run.value.value["pin"], "input_types": specs[p["step_id"]]["inputs"],
                        "output_types": specs[p["step_id"]]["outputs"], "step_version": step["version"],
                        "lease_expires_at_ms": lease["expires_at_ms"], "current": step["attempt_id"] == p["attempt_id"] and step["fence"] == raw["fence"]}
                receipt = tx.get(K.RECEIPT, "receipt-" + p["attempt_id"])
                terminal = receipt.value.value if receipt else None
                data["span"] = {"schema":"runtime.attempt-span.v1", "trace_id":sha256(raw["run_id"].encode())[:32],
                    "span_id":sha256(raw["attempt_id"].encode())[:16], "parent_span_id":sha256(step_key(raw["run_id"],raw["step_id"]).encode())[:16],
                    "started_at_ms":raw["started_at_ms"], "ended_at_ms":terminal["recorded_at_ms"] if terminal else None,
                    "outcome":raw["state"], "actor_id":raw["actor_id"], "fence":raw["fence"]}
            elif op == "output.get":
                data = load(tx, K.OUTPUT_COMMIT, "output-" + p["attempt_id"]).value.value
                if (data["run_id"], data["step_id"]) != (p["run_id"], p["step_id"]):
                    raise DomainError("not_found", "Output does not belong to the requested run and step")
            elif op == "run.get":
                run, specs, steps = self._run_parts(tx, p["run_id"])
                data = {**run.value.value, "steps": [steps[name].value.value for name in sorted(specs)]}
            elif op == "work.list":
                actor = load(tx, K.ACTOR, p["actor_id"])
                self._actor_owner(actor, authority)
                raw = actor.value.value
                worker = Actor(raw["actor_id"], tuple(raw["capabilities"]), tuple(raw["resources"]))
                work, cursor = [], p.get("after")
                for step in records(tx, K.STEP_RUN):
                    if cursor and step.record_id <= cursor:
                        continue
                    raw_step = step.value.value
                    if raw_step["state"] != "ready":
                        continue
                    run, specs, siblings = self._run_parts(tx, raw_step["run_id"])
                    if any(item.value.value["state"] == "failed" for item in siblings.values()):
                        continue
                    spec = specs[raw_step["step_id"]]
                    if run.value.value["state"] in ("pending", "running", "blocked") and not worker.missing(tuple(spec["capabilities"]), tuple(spec["resources"])):
                        work.append({**raw_step, "cursor": step.record_id, "pin": run.value.value["pin"]})
                        if len(work) == p["limit"]:
                            break
                data = {"work": work, "next_cursor": work[-1]["cursor"] if len(work) == p["limit"] else None}
            elif op == "events.list":
                if p["after"] > self.store.event_high_watermark():
                    raise DomainError("cursor_gap", "Event cursor is ahead of this retained stream")
                events = self.store.events(after=p["after"], limit=p["limit"])
                values = [event.value for event in events]
                data = {"events": [event for event in values if "run_id" not in p or event["data"].get("run_id") == p["run_id"]],
                        "next_cursor": values[-1]["sequence"] if values else p["after"], "high_watermark": self.store.event_high_watermark()}
            else:
                raise DomainError("unsupported_contract", "Unknown runtime query")
        return {"schema": "runtime.query-result.v1", "operation": op, "data": data}
