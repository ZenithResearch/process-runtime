"""Persistence conformance: reusable for a future PostgreSQL port adapter."""
import concurrent.futures
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from process_runtime.domain import DomainError, Snapshot
from process_runtime.ports import Record, RecordKind as K, RequestResult
from process_runtime.sqlite_store import SQLiteStore


class PersistenceContract:
    """Adapter implementations run these identical transaction assertions."""
    def item(self, version=1, value=None, kind=K.PROCESS_RUN, name="run-1"):
        return Record(kind, name, version, Snapshot.of(value or {"state": "pending"}))

    def test_atomic_state_event_result_and_replay_rollback(self):
        with self.assertRaisesRegex(RuntimeError, "crash"):
            with self.store.transaction() as tx:
                tx.insert(self.item())
                tx.append_event(Snapshot.of({"event_id": "event-1", "sequence": 1}))
                tx.record_result(RequestResult("subject", "request", "a" * 64, Snapshot.of({"ok": True})))
                tx.admit_replay(subject_id="subject", session_id="session", opcode=1, nonce="nonce", expires_at_ms=10)
                raise RuntimeError("crash")
        self.assertIsNone(self.store.get(K.PROCESS_RUN, "run-1"))
        self.assertEqual(self.store.events(after=0, limit=10), ())
        with self.store.transaction() as tx:
            self.assertIsNone(tx.request_result("subject", "request"))
            tx.admit_replay(subject_id="subject", session_id="session", opcode=1, nonce="nonce", expires_at_ms=10)

    def test_compare_and_swap_and_immutable_commits(self):
        with self.store.transaction() as tx:
            tx.insert(self.item())
            tx.insert(self.item(kind=K.OUTPUT_COMMIT))
        with self.store.transaction() as tx:
            tx.replace(self.item(2, {"state": "running"}), expected_version=1)
        with self.assertRaises(DomainError) as error:
            with self.store.transaction() as tx:
                tx.replace(self.item(2), expected_version=1)
        self.assertEqual(error.exception.code, "version_conflict")
        with self.assertRaises(DomainError) as error:
            with self.store.transaction() as tx:
                tx.replace(self.item(2, kind=K.OUTPUT_COMMIT), expected_version=1)
        self.assertEqual(error.exception.code, "immutable_record")

    def test_competing_writers_observe_one_compare_and_swap_winner(self):
        with self.store.transaction() as tx:
            tx.insert(self.item())
        def claim(index):
            try:
                with self.store.transaction() as tx:
                    tx.replace(self.item(2, {"claimant": index}), expected_version=1)
                return True
            except DomainError as error:
                self.assertEqual(error.code, "version_conflict")
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            self.assertEqual(sum(pool.map(claim, range(12))), 1)

    def test_result_replay_and_ordered_cursor(self):
        with self.store.transaction() as tx:
            tx.record_result(RequestResult("subject", "request", "b" * 64, Snapshot.of({"result": 42})))
            for n in range(3):
                tx.insert(self.item(name=f"run-{n}"))
                self.assertEqual(tx.append_event(Snapshot.of({"event_id": f"e{n}", "sequence": 1})), n+1)
            tx.admit_replay(subject_id="subject", session_id="session", opcode=1, nonce="nonce", expires_at_ms=10)
        with self.store.transaction() as tx:
            self.assertEqual(tx.request_result("subject", "request").response.value, {"result": 42})
            self.assertIsNone(tx.request_result("other", "request"))
            self.assertEqual([r.record_id for r in tx.scan(K.PROCESS_RUN, after="run-0", limit=1)], ["run-1"])
        with self.assertRaises(DomainError) as error:
            with self.store.transaction() as tx:
                tx.admit_replay(subject_id="subject", session_id="session", opcode=1, nonce="nonce", expires_at_ms=20)
        self.assertEqual(error.exception.code, "replay_rejected")
        self.assertEqual([e.value["sequence"] for e in self.store.events(after=1, limit=1)], [2])

    def test_transaction_cannot_escape_commit_or_nest(self):
        with self.store.transaction() as tx:
            tx.insert(self.item())
            with self.assertRaises(DomainError):
                with self.store.transaction():
                    self.fail("nested transaction admitted")
        with self.assertRaises(DomainError):
            tx.insert(self.item(name="run-2"))


class SQLiteConformance(PersistenceContract, unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "runtime.db"
        self.store = SQLiteStore(self.path)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_second_process_writer_is_refused_and_lock_released(self):
        code = 'from process_runtime.sqlite_store import SQLiteStore; SQLiteStore(__import__("sys").argv[1])'
        result = subprocess.run([sys.executable, "-c", code, str(self.path)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Another runtime writer", result.stderr)
        self.store.close()
        self.store = SQLiteStore(self.path)
        self.store.check_integrity()

    def test_real_process_death_before_and_after_commit(self):
        self.store.close()
        code = '''import os,sys
from process_runtime.sqlite_store import SQLiteStore
from process_runtime.ports import Record,RecordKind as K,RequestResult
from process_runtime.domain import Snapshot
s=SQLiteStore(sys.argv[1])
with s.transaction() as tx:
 tx.insert(Record(K.OUTPUT_COMMIT, "commit", 1, Snapshot.of({"outputs":{"answer":42}})))
 tx.insert(Record(K.PROCESS_RUN, "run", 1, Snapshot.of({"state":"succeeded"})))
 tx.append_event(Snapshot.of({"sequence":1,"kind":"completed"}))
 tx.record_result(RequestResult("actor","request","a"*64,Snapshot.of({"ok":True})))
 if sys.argv[2]=="before": os._exit(71)
os._exit(72)
'''
        for phase, exists in (("before", False), ("after", True)):
            result = subprocess.run([sys.executable, "-c", code, str(self.path), phase], capture_output=True)
            self.assertEqual(result.returncode, 71 if phase == "before" else 72, result.stderr.decode())
            self.store = SQLiteStore(self.path)
            self.assertEqual(self.store.get(K.OUTPUT_COMMIT, "commit") is not None, exists)
            self.assertEqual(self.store.get(K.PROCESS_RUN, "run") is not None, exists)
            self.assertEqual(len(self.store.events(after=0, limit=10)), int(exists))
            with self.store.transaction() as tx:
                self.assertEqual(tx.request_result("actor", "request") is not None, exists)
            self.store.close()

    def test_schema_mismatch_and_corrupt_records_fail_closed(self):
        with self.store.transaction() as tx:
            tx.insert(self.item())
        self.store.close()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE process_run SET body='{}'")
        with self.assertRaises(DomainError) as error:
            SQLiteStore(self.path)
        self.assertEqual(error.exception.code, "storage_unavailable")
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA user_version=999")
        with self.assertRaises(DomainError) as error:
            SQLiteStore(self.path)
        self.assertEqual(error.exception.code, "incompatible_version")

    def test_immutable_guards_and_migration_checksum_are_persistent(self):
        with self.store.transaction() as tx:
            tx.insert(self.item(kind=K.RECEIPT))
        self.store.close()
        with sqlite3.connect(self.path) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM receipt")
            db.execute("UPDATE migration_journal SET checksum='changed'")
        with self.assertRaises(DomainError) as error:
            SQLiteStore(self.path)
        self.assertEqual(error.exception.code, "incompatible_version")

    def test_symlink_and_public_directory_are_rejected(self):
        link = Path(self.temp.name) / "link.db"
        link.symlink_to(self.path)
        with self.assertRaises(DomainError):
            SQLiteStore(link)
        hardlink = Path(self.temp.name) / "hardlink.db"
        os.link(self.path, hardlink)
        with self.assertRaises(DomainError):
            SQLiteStore(hardlink)
        hardlink.unlink()
        public = Path(self.temp.name) / "public"
        public.mkdir(mode=0o755)
        with self.assertRaises(DomainError):
            SQLiteStore(public / "new.db")

if __name__ == "__main__":
    unittest.main()
