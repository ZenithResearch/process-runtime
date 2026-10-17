"""Verified request snapshots must own every read, gate, result and replay field."""
from copy import deepcopy
import unittest
from unittest.mock import patch

import test_application as fixture
from process_runtime.admission import StaticAdmissionGate
from process_runtime.contracts import validate
from process_runtime.domain import DomainError
from process_runtime.ports import RecordKind


class RequestSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.RuntimeApplicationTests()
        self.f.setUp()
        self.addCleanup(self.f.tearDown)

    def mutating_verifier(self, mutate):
        delegate = self.f.verifier
        class Verifier:
            def verify(self, **kwargs):
                verified = delegate.verify(**kwargs)
                mutate()
                return verified
        self.f.runtime.verifier = Verifier()

    def test_query_cannot_read_resource_substituted_during_verification(self):
        f = self.f
        f.command("run.create", {"run_id": "private-run", "pin": f.pin, "inputs": {"number": 99}}, None)
        request = {"schema": "runtime.query.v1", "operation": "run.get", "payload": {"run_id": "run-1"}}
        self.mutating_verifier(lambda: request["payload"].update(run_id="private-run"))
        result = f.runtime.query(request)
        self.assertEqual(result["data"]["run_id"], "run-1")
        self.assertEqual(result["data"]["inputs"], {"number": 7})
        self.assertEqual(request["payload"]["run_id"], "private-run")

    def test_command_result_events_and_replay_keep_verified_identity(self):
        f = self.f
        request = f.envelope("run.create", {"run_id": "snapshot-run", "pin": f.pin, "inputs": {"number": 3}}, None)
        original = deepcopy(request)
        before = f.store.event_high_watermark()
        def mutate():
            request.update(request_id="substituted-request", resource="runs/private-run")
            request["payload"].update(run_id="private-run", inputs={"number": 99})
        self.mutating_verifier(mutate)
        result = f.runtime.execute(request)
        self.assertEqual(result["request_id"], original["request_id"])
        self.assertEqual(result["resource"], original["resource"])
        self.assertEqual(result["result"]["run_id"], "snapshot-run")
        self.assertIsNone(f.store.get(RecordKind.PROCESS_RUN, "private-run"))
        events = [event.value for event in f.store.events(after=before, limit=100)]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["request_id"], original["request_id"])
        self.assertEqual(events[0]["resource"], original["resource"])
        f.runtime.verifier = f.verifier
        self.assertTrue(f.runtime.execute(original)["duplicate"])
        self.assertEqual(f.store.event_high_watermark(), before + 1)

    def test_operation_mutation_after_validation_cannot_bypass_closed_admission(self):
        f = self.f
        f.runtime.new_run_admission = StaticAdmissionGate(False)
        request = f.envelope("run.create", {"run_id": "denied-run", "pin": f.pin, "inputs": {"number": 3}}, None)
        before = f.store.event_high_watermark()
        def validate_and_mutate(value, kind):
            snapshot = validate(value, kind)
            if kind == "command":
                value["operation"] = "process.draft.put"
            return snapshot
        with patch("process_runtime.application.validate", side_effect=validate_and_mutate):
            with self.assertRaises(DomainError) as caught:
                f.runtime.execute(request)
        self.assertEqual(caught.exception.code, "not_ready")
        self.assertIsNone(f.store.get(RecordKind.PROCESS_RUN, "denied-run"))
        self.assertEqual(f.store.event_high_watermark(), before)

    def test_queued_query_does_not_share_nested_caller_inputs(self):
        f = self.f
        request = {"schema": "runtime.query.v1", "operation": "run.get", "payload": {"run_id": "run-1"}}
        original_transaction = f.store.transaction
        from contextlib import contextmanager
        @contextmanager
        def mutate_before_transaction():
            request["payload"]["run_id"] = "missing-private-run"
            with original_transaction() as tx:
                yield tx
        f.store.transaction = mutate_before_transaction
        self.assertEqual(f.runtime.query(request)["data"]["run_id"], "run-1")


if __name__ == "__main__": unittest.main()
