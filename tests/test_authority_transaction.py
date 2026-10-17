"""Admission must use current time/policy after waiting for the writer mutex."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import threading
import unittest

import test_application as application_fixture
from process_runtime.domain import DomainError
from process_runtime.ports import RecordKind


class AuthorityTransactionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = application_fixture.RuntimeApplicationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def queued(self, action, while_waiting):
        store = self.fixture.store
        original = store.transaction
        waiting = threading.Event()
        @contextmanager
        def signalled_transaction():
            waiting.set()
            with original() as transaction:
                yield transaction
        pool = ThreadPoolExecutor(max_workers=1)
        try:
            with original():
                store.transaction = signalled_transaction
                future = pool.submit(action)
                self.assertTrue(waiting.wait(2), "Request never reached transaction admission")
                while_waiting()
            return future.result(timeout=5)
        finally:
            store.transaction = original
            pool.shutdown(wait=True)

    def test_queued_command_rechecks_proof_expiry_before_mutation(self):
        f = self.fixture
        f.verifier.override = {"issued_at_ms": 1000, "expires_at_ms": 2000}
        command = f.envelope("run.create", {"run_id": "queued-run", "pin": f.pin, "inputs": {"number": 1}}, None)
        with self.assertRaises(DomainError) as caught:
            self.queued(lambda: f.runtime.execute(command), lambda: f.now.__setitem__(0, 2000))
        self.assertEqual(caught.exception.code, "unauthenticated")
        self.assertIsNone(f.store.get(RecordKind.PROCESS_RUN, "queued-run"))

    def test_queued_query_rechecks_proof_expiry_before_read(self):
        f = self.fixture
        f.verifier.override = {"issued_at_ms": 1000, "expires_at_ms": 2000}
        with self.assertRaises(DomainError) as caught:
            self.queued(lambda: f.query("run.get", {"run_id": "run-1"}), lambda: f.now.__setitem__(0, 2000))
        self.assertEqual(caught.exception.code, "unauthenticated")

    def test_queued_completion_cannot_use_expired_lease(self):
        f = self.fixture
        claim = f.claim()
        command = f.envelope("executor.complete", {**f.binding(claim), "outputs": {"answer": 14}}, f.step()["version"])
        with self.assertRaises(DomainError) as caught:
            self.queued(lambda: f.runtime.execute(command), lambda: f.now.__setitem__(0, 2000))
        self.assertEqual(caught.exception.code, "lease_expired")
        self.assertIsNone(f.store.get(RecordKind.OUTPUT_COMMIT, "output-" + claim["result"]["attempt_id"]))
        self.assertEqual(f.step()["state"], "running")

    def test_queued_exact_duplicate_rechecks_current_revocation(self):
        f = self.fixture
        command = f.envelope("run.create", {"run_id": "duplicate-run", "pin": f.pin, "inputs": {"number": 1}}, None)
        f.runtime.execute(command)
        delegate = f.verifier
        class CurrentVerifier:
            revoked = False
            def verify(self, **kwargs):
                if self.revoked:
                    raise DomainError("forbidden", "Current receiver policy revoked authority")
                return delegate.verify(**kwargs)
        current = CurrentVerifier()
        f.runtime.verifier = current
        with self.assertRaises(DomainError) as caught:
            self.queued(lambda: f.runtime.execute(command), lambda: setattr(current, "revoked", True))
        self.assertEqual(caught.exception.code, "forbidden")
        self.assertEqual(f.store.get(RecordKind.PROCESS_RUN, "duplicate-run").version, 1)

    def test_verifier_latency_cannot_extend_proof_or_lease(self):
        f = self.fixture
        claim = f.claim()
        command = f.envelope("executor.complete", {**f.binding(claim), "outputs": {"answer": 14}}, f.step()["version"])
        delegate = f.verifier
        class SlowVerifier:
            def verify(self, **kwargs):
                verified = delegate.verify(**kwargs)
                f.now[0] = 2000
                return verified
        f.runtime.verifier = SlowVerifier()
        with self.assertRaises(DomainError) as caught:
            f.runtime.execute(command)
        self.assertEqual(caught.exception.code, "lease_expired")
        self.assertIsNone(f.store.get(RecordKind.OUTPUT_COMMIT, "output-" + claim["result"]["attempt_id"]))


if __name__ == "__main__":
    unittest.main()
