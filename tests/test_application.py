import concurrent.futures
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
import uuid

from process_runtime.application import Runtime
from process_runtime.contracts import validate
from process_runtime.domain import DomainError, Snapshot
from process_runtime.ports import VerifiedAuthority, RecordKind as K
from process_runtime.sqlite_store import SQLiteStore


def draft():
    return {"schema": "process.draft.v1", "process_id": "development-sop", "inputs": {"number": {"kind": "integer"}},
            "steps": [
                {"step_id": "z-source", "depends_on": [], "capabilities": ["compute"], "resources": [],
                 "inputs": {"number": {"kind": "integer"}}, "bindings": {"number": {"source": "run_input", "name": "number"}},
                 "outputs": {"answer": {"kind": "integer"}}, "max_attempts": 3},
                {"step_id": "a-consumer", "depends_on": ["z-source"], "capabilities": ["compute"], "resources": [],
                 "inputs": {"previous": {"kind": "integer"}}, "bindings": {"previous": {"source": "step_output", "step_id": "z-source", "name": "answer"}},
                 "outputs": {"done": {"kind": "boolean"}}, "max_attempts": 2}]}


class TestVerifier:
    """Explicit non-authoritative test fixture; never shipped as an issuer."""
    subject = "test-subject"
    override = None
    def verify(self, *, envelope, command, now_ms):
        from process_runtime.authority import resource_for, OPCODES
        op = command.value["operation"]
        value = VerifiedAuthority(self.subject, "test-key", "runtime://receiver-local", op, resource_for(command),
              command.digest, now_ms, now_ms + 10000, "1" * 32, OPCODES[op], uuid.uuid4().hex[:24], "a" * 64, "local_dev_untrusted")
        return replace(value, **self.override) if self.override else value


class RuntimeApplicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "runtime.db"
        self.store = SQLiteStore(self.path)
        self.now = [1000]
        self.verifier = TestVerifier()
        self.runtime = Runtime(self.store, verifier=self.verifier, environment="test", allow_local_dev_untrusted=True, clock=lambda: self.now[0])
        self.provenance = {"source_id": "development-source", "media_type": "application/json", "content_hash": Snapshot.of(draft()).digest, "parser": "explicit-json-v1", "uncertainties": []}
        self.command("process.draft.put", {"draft": draft(), "provenance": self.provenance}, None)
        self.pin = self.command("process.publish", {"process_id": "development-sop", "draft_revision": 1, "version_id": "development-v1"}, 1)["result"]["pin"]
        self.command("actor.register", {"actor_id": "worker", "capabilities": ["compute"], "resources": []}, None)
        self.command("run.create", {"run_id": "run-1", "pin": self.pin, "inputs": {"number": 7}}, None)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def envelope(self, operation, payload, version, request_id=None):
        from process_runtime.authority import resource_for
        value = {"schema": "runtime.command.v1", "operation": operation, "request_id": request_id or str(uuid.uuid4()),
                 "resource": "placeholder", "expected_version": version, "payload": payload}
        value["resource"] = resource_for(Snapshot.of(value))
        return value

    def command(self, operation, payload, version, request_id=None):
        return self.runtime.execute(self.envelope(operation, payload, version, request_id))

    def query(self, operation, payload):
        return self.runtime.query({"schema": "runtime.query.v1", "operation": operation, "payload": payload})["data"]

    def step(self, step_id="z-source"):
        return next(s for s in self.query("run.get", {"run_id": "run-1"})["steps"] if s["step_id"] == step_id)

    def claim(self, step_id="z-source"):
        return self.command("executor.claim", {"run_id": "run-1", "step_id": step_id, "actor_id": "worker", "lease_ms": 1000}, self.step(step_id)["version"])

    @staticmethod
    def binding(claim):
        return {k: claim["result"][k] for k in ("run_id", "step_id", "attempt_id", "fence")}

    def complete(self, claim, outputs):
        return self.command("executor.complete", {**self.binding(claim), "outputs": outputs}, self.step(claim["result"]["step_id"])["version"])

    def test_dag_readiness_and_immutable_output_before_downstream_claim(self):
        work = self.query("work.list", {"actor_id": "worker", "limit": 100})
        self.assertEqual([s["step_id"] for s in work["work"]], ["z-source"])
        with self.assertRaises(DomainError):
            self.claim("a-consumer")
        first = self.claim()
        self.assertEqual(first["result"]["inputs"], {"number": 7})
        complete = self.complete(first, {"answer": 14})
        output = self.query("output.get", {"run_id": "run-1", "step_id": "z-source", "attempt_id": first["result"]["attempt_id"]})
        receipt = self.query("receipt.get", {"receipt_id": complete["result"]["receipt_id"]})
        validate(receipt, "receipt")
        self.assertEqual(output["output_digest"], Snapshot.of({"answer": 14}).digest)
        self.assertEqual(receipt["output_digest"], output["output_digest"])
        second = self.claim("a-consumer")
        self.assertEqual(second["result"]["inputs"], {"previous": 14})
        self.complete(second, {"done": True})
        self.assertEqual(self.query("run.get", {"run_id": "run-1"})["state"], "succeeded")
        events = self.query("events.list", {"after": 0, "limit": 100})
        kinds = [event["kind"] for event in events["events"]]
        self.assertLess(kinds.index("output.committed"), kinds.index("attempt.completed"))
        self.assertEqual(events["high_watermark"], events["next_cursor"])

    def test_publication_never_repins_existing_run_and_invalid_dag_cannot_publish(self):
        changed = draft(); changed["steps"][0]["max_attempts"] = 9
        self.command("process.draft.put", {"draft": changed, "provenance": self.provenance}, 2)
        version = self.command("process.publish", {"process_id": "development-sop", "draft_revision": 2, "version_id": "development-v2"}, 3)
        self.assertNotEqual(version["result"]["pin"], self.pin)
        self.assertEqual(self.query("run.get", {"run_id": "run-1"})["pin"], self.pin)
        changed["steps"][0]["depends_on"] = ["a-consumer"]
        self.command("process.draft.put", {"draft": changed, "provenance": self.provenance}, 4)
        with self.assertRaises(DomainError) as caught:
            self.command("process.publish", {"process_id": "development-sop", "draft_revision": 3, "version_id": "invalid"}, 5)
        self.assertEqual(caught.exception.code, "invalid_dag")
        self.assertIsNone(self.store.get(K.PROCESS_VERSION, "invalid"))

    def test_atomic_claim_has_one_winner_and_owner_binding(self):
        commands = [self.envelope("executor.claim", {"run_id": "run-1", "step_id": "z-source", "actor_id": "worker", "lease_ms": 1000}, 1) for _ in range(12)]
        def execute(command):
            try:
                self.runtime.execute(command); return True
            except DomainError as error:
                self.assertIn(error.code, ("version_conflict", "not_ready")); return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            self.assertEqual(sum(pool.map(execute, commands)), 1)
        self.verifier.subject = "other-subject"
        with self.assertRaises(DomainError) as caught:
            self.query("work.list", {"actor_id": "worker", "limit": 10})
        self.assertEqual(caught.exception.code, "forbidden")

    def test_complete_type_failure_rolls_back_then_exact_retry_survives_restart(self):
        claim = self.claim()
        with self.assertRaises(DomainError):
            self.complete(claim, {"answer": True})
        self.assertEqual(self.step()["state"], "running")
        command = self.envelope("executor.complete", {**self.binding(claim), "outputs": {"answer": 14}}, self.step()["version"], "lost-response")
        first = self.runtime.execute(command)
        self.store.close(); self.store = SQLiteStore(self.path)
        self.runtime = Runtime(self.store, verifier=self.verifier, environment="test", allow_local_dev_untrusted=True, clock=lambda: self.now[0])
        retry = self.runtime.execute(command)
        self.assertEqual(retry, {**first, "duplicate": True})
        changed = deepcopy(command); changed["payload"]["outputs"]["answer"] = 20
        with self.assertRaises(DomainError) as caught:
            self.runtime.execute(changed)
        self.assertEqual(caught.exception.code, "idempotency_conflict")

    def test_heartbeat_fences_and_expiry_create_new_attempt(self):
        first = self.claim()
        self.command("executor.heartbeat", {**self.binding(first), "lease_ms": 2000}, first["version"])
        self.now[0] = 2500
        self.assertEqual(self.runtime.recover(), 0)
        self.now[0] = 3000
        self.assertEqual(self.runtime.recover(), 1)
        self.assertEqual(self.runtime.recover(), 0)
        second = self.claim()
        self.assertNotEqual(second["result"]["attempt_id"], first["result"]["attempt_id"])
        self.assertGreater(second["result"]["fence"], first["result"]["fence"])
        with self.assertRaises(DomainError) as caught:
            self.command("executor.complete", {**self.binding(first), "outputs": {"answer": 4}}, second["version"])
        self.assertEqual(caught.exception.code, "stale_fence")
        receipt = self.query("receipt.get", {"receipt_id": "receipt-" + first["result"]["attempt_id"]})
        self.assertEqual(receipt["outcome"], "expired")

    def test_retryable_failure_is_explicit_and_creates_new_attempt(self):
        first = self.claim()
        self.command("executor.fail", {**self.binding(first), "reason": "temporary failure", "retryable": True}, first["version"])
        self.assertEqual(self.step()["state"], "blocked")
        run = self.query("run.get", {"run_id": "run-1"})
        self.command("run.retry", {"run_id": "run-1", "step_id": "z-source", "reason": "retry approved"}, run["version"])
        second = self.claim()
        self.assertNotEqual(first["result"]["attempt_id"], second["result"]["attempt_id"])
        self.assertEqual(self.store.get(K.ATTEMPT, second["result"]["attempt_id"]).value.value["ordinal"], 2)

    def test_unknown_effect_blocks_recovery_retry_and_completion_until_reconciled(self):
        claim = self.claim(); binding = self.binding(claim)
        effect = self.command("executor.effect.intent", {**binding, "effect_name": "send", "integration": "matrix", "request_digest": "b"*64, "provider_idempotent": True}, self.step()["version"])
        effect_id = effect["result"]["effect_id"]
        self.command("executor.effect.dispatch", {**binding, "effect_id": effect_id}, self.step()["version"])
        self.command("executor.effect.observe", {**binding, "effect_id": effect_id, "provider_reference": "remote-1", "outcome": "acknowledged", "observation_digest": "c"*64}, self.step()["version"])
        with self.assertRaises(DomainError):
            self.complete(claim, {"answer": 1})
        self.now[0] = 2000; self.runtime.recover()
        self.assertEqual(self.query("effect.get", {"effect_id": effect_id})["state"], "unknown")
        run = self.query("run.get", {"run_id": "run-1"})
        retry = {"run_id": "run-1", "step_id": "z-source", "reason": "retry"}
        with self.assertRaises(DomainError) as caught:
            self.command("run.retry", retry, run["version"])
        self.assertEqual(caught.exception.code, "unknown_outcome")
        effect = self.query("effect.get", {"effect_id": effect_id})
        self.command("effect.resolve", {"effect_id": effect_id, "outcome": "failed", "provider_reference": "remote-1", "observation_digest": "d"*64, "reason": "Provider confirmed no delivery"}, effect["version"])
        self.command("run.retry", retry, run["version"])
        self.claim()

    def test_successful_effect_is_not_silently_repeated_after_lost_output(self):
        claim = self.claim(); binding = self.binding(claim)
        effect = self.command("executor.effect.intent", {**binding, "effect_name": "send", "integration": "hermes", "request_digest": "b"*64, "provider_idempotent": False}, self.step()["version"])["result"]
        self.command("executor.effect.dispatch", {**binding, "effect_id": effect["effect_id"]}, self.step()["version"])
        self.command("executor.effect.observe", {**binding, "effect_id": effect["effect_id"], "provider_reference": "remote-1", "outcome": "succeeded", "observation_digest": "c"*64}, self.step()["version"])
        self.now[0] = 2000; self.runtime.recover()
        run = self.query("run.get", {"run_id": "run-1"})
        self.assertEqual(run["state"], "blocked")
        with self.assertRaises(DomainError):
            self.command("run.retry", {"run_id": "run-1", "step_id": "z-source", "reason": "retry"}, run["version"])

    def test_handoff_inbox_duplicate_and_changed_source_event(self):
        payload = {"schema": "service.runtime-handoff.v1", "event_id": "event-1", "source": "service-management",
                   "request_id": "service-request", "case_id": "case-1", "plan_revision_id": "revision-1",
                   "pin": self.pin, "inputs": {"number": 8}, "idempotency_key": "handoff-1"}
        first = self.command("handoff.consume", payload, None)
        second = self.command("handoff.consume", payload, None)
        self.assertEqual(first["result"]["run_id"], second["result"]["run_id"])
        payload["inputs"]["number"] = 9
        with self.assertRaises(DomainError) as caught:
            self.command("handoff.consume", payload, None)
        self.assertEqual(caught.exception.code, "idempotency_conflict")

    def test_cancellation_receipts_and_wrong_resource_authority_fail_closed(self):
        claim = self.claim()
        run = self.query("run.get", {"run_id": "run-1"})
        self.command("run.cancel", {"run_id": "run-1", "reason": "owner cancellation"}, run["version"])
        self.assertEqual(self.query("receipt.get", {"receipt_id": "receipt-" + claim["result"]["attempt_id"]})["outcome"], "cancelled")
        with self.assertRaises(DomainError):
            self.complete(claim, {"answer": 1})
        command = self.envelope("run.create", {"run_id": "wrong", "pin": self.pin, "inputs": {"number": 1}}, None)
        command["resource"] = "runs/other"
        with self.assertRaises(DomainError):
            self.runtime.execute(command)

    def test_default_deny_and_production_reject_local_development(self):
        with self.assertRaises(ValueError):
            Runtime(self.store, environment="production", allow_local_dev_untrusted=True)
        protected = Runtime(self.store)
        with self.assertRaises(DomainError):
            protected.query({"schema": "runtime.query.v1", "operation": "run.get", "payload": {"run_id": "run-1"}})
        production = Runtime(self.store, verifier=self.verifier)
        with self.assertRaises(DomainError):
            production.query({"schema": "runtime.query.v1", "operation": "run.get", "payload": {"run_id": "run-1"}})
        for changed in ({"request_digest": "0"*64}, {"audience": "another-receiver"}, {"resource": "runs/wrong"}, {"expires_at_ms": 1000}):
            self.verifier.override = changed
            with self.assertRaises(DomainError):
                self.query("run.get", {"run_id": "run-1"})

    def test_receipt_chain_rejects_changed_bindings_and_outputs(self):
        from process_runtime.receipt_verifier import verify_receipt
        claim = self.claim(); complete = self.complete(claim, {"answer":14})
        fields = {"run_id":"run-1", "step_id":"z-source", "attempt_id":claim["result"]["attempt_id"]}
        receipt = self.query("receipt.get", {"receipt_id":complete["result"]["receipt_id"]})
        version = self.query("version.get", {"process_version":self.pin["process_version"]})
        attempt = self.query("attempt.get", fields)
        output = self.query("output.get", fields)
        verify_receipt(receipt, version=version, attempt=attempt, output=output)
        for key, changed in (("actor_id","other"),("attempt_id","other"),("fence",99),("input_digest","e"*64),("output_digest","e"*64),("run_id","other"),("step_id","other")):
            tampered=deepcopy(receipt);tampered[key]=changed
            with self.subTest(key=key),self.assertRaises(DomainError):
                verify_receipt(tampered,version=version,attempt=attempt,output=output)
        changed=deepcopy(output);changed["outputs"]["answer"]=99
        with self.assertRaises(DomainError):
            verify_receipt(receipt,version=version,attempt=attempt,output=changed)
        changed=deepcopy(version);changed["compiled"]["steps"][0]["max_attempts"]=99
        with self.assertRaises(DomainError):
            verify_receipt(receipt,version=changed,attempt=attempt,output=output)

    def test_wakeup_loss_never_loses_committed_execution_or_outbox(self):
        class BrokenBus:
            def notify(self, sequence):
                raise OSError("bus unavailable")
        self.runtime.wakeups=BrokenBus()
        self.claim()
        self.assertEqual(self.step()["state"],"running")
        class Bus:
            def __init__(self): self.sequences=[]
            def notify(self, sequence): self.sequences.append(sequence)
        bus=Bus();self.runtime.wakeups=bus
        delivered=self.runtime.flush_wakeups()
        self.assertEqual(delivered,self.store.event_high_watermark())
        self.assertEqual(len(set(bus.sequences)),delivered)
        self.assertEqual(self.runtime.flush_wakeups(),0)

if __name__ == "__main__":
    unittest.main()
