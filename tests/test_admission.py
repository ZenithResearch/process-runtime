import concurrent.futures
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import tempfile
import threading
import unittest
import uuid

from process_runtime.admission import (AdmissionPolicyError, FileAdmissionGate, SCHEMA,
    apply_policy, read_policy)
from process_runtime.application import Runtime
from process_runtime.domain import DomainError, Snapshot
from process_runtime.ports import RecordKind as K
from process_runtime.sqlite_store import SQLiteStore
from test_application import draft, TestVerifier


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.policy = Path(self.temp.name) / 'admission.json'
        self.value = {'schema': SCHEMA, 'enabled': True, 'composition_digest': 'a' * 64}
        self.digest = apply_policy(self.policy, self.value, expected_digest=None)['policy_digest']
        self.store = SQLiteStore(Path(self.temp.name) / 'runtime.db')
        self.runtime = Runtime(self.store, verifier=TestVerifier(), environment='test', allow_local_dev_untrusted=True,
                               clock=lambda: 1000, new_run_admission=FileAdmissionGate(self.policy))
        self.call('process.draft.put', {'draft': draft(), 'provenance': {'source_id': 'test', 'media_type': 'application/json',
            'content_hash': Snapshot.of(draft()).digest, 'parser': 'explicit-json-v1', 'uncertainties': []}})
        self.pin = self.call('process.publish', {'process_id': 'development-sop', 'draft_revision': 1, 'version_id': 'v1'}, 1)['result']['pin']
        self.call('actor.register', {'actor_id': 'worker', 'capabilities': ['compute'], 'resources': []})

    def tearDown(self):
        self.store.close(); self.temp.cleanup()

    def command(self, op, payload, version=None, request_id=None):
        from process_runtime.authority import resource_for
        value = {'schema': 'runtime.command.v1', 'operation': op, 'request_id': request_id or uuid.uuid4().hex,
                 'resource': 'placeholder', 'expected_version': version, 'payload': payload}
        value['resource'] = resource_for(Snapshot.of(value))
        return value

    def call(self, op, payload, version=None, request_id=None):
        return self.runtime.execute(self.command(op, payload, version, request_id))

    def close(self):
        self.digest = apply_policy(self.policy, {**self.value, 'enabled': False}, expected_digest=self.digest)['policy_digest']

    def test_rollback_denies_new_runs_but_keeps_exact_retry_existing_claim_and_output(self):
        original = self.command('run.create', {'run_id': 'existing', 'pin': self.pin, 'inputs': {'number': 7}})
        self.runtime.execute(original)
        self.close()
        before = self.store.event_high_watermark()
        with self.assertRaises(DomainError) as error:
            self.call('run.create', {'run_id': 'late', 'pin': self.pin, 'inputs': {'number': 7}})
        self.assertEqual(error.exception.code, 'not_ready')
        self.assertIsNone(self.store.get(K.PROCESS_RUN, 'late'))
        self.assertEqual(self.store.event_high_watermark(), before)
        self.assertTrue(self.runtime.execute(original)['duplicate'])
        query = self.runtime.query({'schema': 'runtime.query.v1', 'operation': 'run.get', 'payload': {'run_id': 'existing'}})['data']
        step = next(x for x in query['steps'] if x['step_id'] == 'z-source')
        claim = self.call('executor.claim', {'run_id': 'existing', 'step_id': 'z-source', 'actor_id': 'worker', 'lease_ms': 1000}, step['version'])
        binding = {k: claim['result'][k] for k in ('run_id', 'step_id', 'attempt_id', 'fence')}
        self.call('executor.complete', {**binding, 'outputs': {'answer': 14}}, claim['result']['step_version'])
        output = self.runtime.query({'schema': 'runtime.query.v1', 'operation': 'output.get', 'payload': {k: binding[k] for k in ('run_id', 'step_id', 'attempt_id')}})['data']
        self.assertEqual(output['output_digest'], Snapshot.of({'answer': 14}).digest)

    def test_handoff_reconciliation_allowed_after_close_new_event_blocked(self):
        event = {'schema': 'service.runtime-handoff.v1', 'source': 'service-management', 'event_id': 'event-1',
            'idempotency_key': 'handoff-one', 'request_id': 'request-1', 'case_id': 'case-1',
            'plan_revision_id': None, 'pin': self.pin, 'inputs': {'number': 7}}
        first = self.call('handoff.consume', event)
        self.close()
        second = self.call('handoff.consume', event)
        self.assertEqual(first['result']['run_id'], second['result']['run_id'])
        changed = {**event, 'event_id': 'event-2', 'idempotency_key': 'handoff-two'}
        with self.assertRaises(DomainError) as error: self.call('handoff.consume', changed)
        self.assertEqual(error.exception.code, 'not_ready')

    def test_restart_reads_closed_policy(self):
        self.close(); self.store.close()
        self.store = SQLiteStore(Path(self.temp.name) / 'runtime.db')
        self.runtime = Runtime(self.store, verifier=TestVerifier(), environment='test', allow_local_dev_untrusted=True,
                               clock=lambda: 1000, new_run_admission=FileAdmissionGate(self.policy))
        with self.assertRaises(DomainError) as error:
            self.call('run.create', {'run_id': 'after-restart', 'pin': self.pin, 'inputs': {'number': 7}})
        self.assertEqual(error.exception.code, 'not_ready')

    def test_missing_malformed_shared_or_symlink_policy_fails_closed(self):
        for bad in ('missing', 'malformed', 'shared', 'symlink'):
            with self.subTest(bad=bad):
                if self.policy.exists() or self.policy.is_symlink(): self.policy.unlink()
                if bad == 'malformed': self.policy.write_text('{'); self.policy.chmod(0o600)
                if bad == 'shared': self.policy.write_text('{}'); self.policy.chmod(0o644)
                if bad == 'symlink': self.policy.symlink_to(Path(self.temp.name) / 'elsewhere')
                with self.assertRaises(DomainError) as error:
                    self.call('run.create', {'run_id': 'invalid-' + bad, 'pin': self.pin, 'inputs': {'number': 7}})
                self.assertEqual(error.exception.code, 'not_ready')

    def test_compare_and_swap_refuses_stale_or_shared_policy_without_change(self):
        original = self.policy.read_bytes()
        with self.assertRaises(AdmissionPolicyError):
            apply_policy(self.policy, {**self.value, 'enabled': False}, expected_digest='0' * 64)
        self.assertEqual(self.policy.read_bytes(), original)
        self.policy.chmod(0o644)
        with self.assertRaises(AdmissionPolicyError):
            apply_policy(self.policy, {**self.value, 'enabled': False}, expected_digest=self.digest)
        self.assertEqual(self.policy.read_bytes(), original)

    def test_apply_waits_for_admitted_transaction_to_commit_then_stops_later_work(self):
        reached, release, attempted = threading.Event(), threading.Event(), threading.Event()
        original_transaction = self.store.transaction
        @contextmanager
        def paused_commit():
            with original_transaction() as tx:
                yield tx
                reached.set()
                if not release.wait(5): raise AssertionError('Commit release timed out')
        self.store.transaction = paused_commit
        command = self.command('run.create', {'run_id': 'admitted-before-close', 'pin': self.pin, 'inputs': {'number': 7}})
        def apply_close():
            attempted.set()
            return apply_policy(self.policy, {**self.value, 'enabled': False}, expected_digest=self.digest)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            running = pool.submit(self.runtime.execute, command)
            self.assertTrue(reached.wait(5))
            changing = pool.submit(apply_close)
            self.assertTrue(attempted.wait(5))
            try:
                with self.assertRaises(concurrent.futures.TimeoutError): changing.result(timeout=.1)
            finally: release.set()
            running.result(timeout=5); changing.result(timeout=5)
        self.store.transaction = original_transaction
        self.assertIsNotNone(self.store.get(K.PROCESS_RUN, 'admitted-before-close'))
        with self.assertRaises(DomainError):
            self.call('run.create', {'run_id': 'after-close', 'pin': self.pin, 'inputs': {'number': 7}})


if __name__ == '__main__': unittest.main()
