"""SQLite adapter: a single process writer, explicit atomic units of work.

WAL is an adapter choice. The application and domain depend only on ports.
Durable request results, replay admission, records and events share a commit.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import sqlite3
import stat
import threading

from .domain import DomainError, Snapshot, identifier, positive, sha256
from .ports import Record, RecordKind, RequestResult

IMMUTABLE = frozenset((RecordKind.PROCESS_VERSION, RecordKind.OUTPUT_COMMIT,
                       RecordKind.ARTIFACT, RecordKind.RECEIPT, RecordKind.INBOX))
SCHEMA_VERSION = 1
STATEMENTS = [
    "CREATE TABLE migration_journal (version INTEGER PRIMARY KEY, checksum TEXT NOT NULL)",
    "CREATE TABLE request_results (subject TEXT NOT NULL, request_id TEXT NOT NULL, digest TEXT NOT NULL, response TEXT NOT NULL, response_hash TEXT NOT NULL, PRIMARY KEY(subject,request_id))",
    "CREATE TABLE replay_admissions (subject TEXT NOT NULL, session TEXT NOT NULL, opcode INTEGER NOT NULL, nonce TEXT NOT NULL, expires_at_ms INTEGER NOT NULL, PRIMARY KEY(subject,session,opcode,nonce))",
    "CREATE TABLE events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL, body_hash TEXT NOT NULL)",
]
for kind in RecordKind:
    STATEMENTS.append(f"CREATE TABLE {kind.value} (id TEXT PRIMARY KEY, version INTEGER NOT NULL CHECK(version>0), body TEXT NOT NULL, body_hash TEXT NOT NULL)")
for table in sorted(kind.value for kind in IMMUTABLE) + ["events", "request_results", "replay_admissions"]:
    for action in ("UPDATE", "DELETE"):
        STATEMENTS.append(f"CREATE TRIGGER immutable_{table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'immutable_record'); END")
SCHEMA_CHECKSUM = sha256("\n".join(STATEMENTS).encode())


def _snapshot(body: str, expected_hash: str) -> Snapshot:
    value = Snapshot(body)
    if value.digest != expected_hash:
        raise DomainError("storage_unavailable", "Stored content failed its integrity check")
    return value


def _record(kind: RecordKind, row) -> Record | None:
    return None if row is None else Record(kind, row[0], row[1], _snapshot(row[2], row[3]))


def _check_record(record: Record) -> None:
    if not isinstance(record.kind, RecordKind) or not isinstance(record.value, Snapshot):
        raise DomainError("invalid_value", "Record kind and immutable value are required")
    identifier(record.record_id)
    positive(record.version, "record version")


class SQLiteTransaction:
    def __init__(self, connection: sqlite3.Connection):
        self._connection = connection
        self._active = True

    def _db(self):
        if not self._active:
            raise DomainError("storage_unavailable", "Transaction is no longer active")
        return self._connection

    def get(self, kind: RecordKind, record_id: str) -> Record | None:
        kind = RecordKind(kind)
        return _record(kind, self._db().execute(f"SELECT id,version,body,body_hash FROM {kind.value} WHERE id=?", (record_id,)).fetchone())

    def scan(self, kind: RecordKind, *, after: str | None = None, limit: int = 100) -> tuple[Record, ...]:
        kind = RecordKind(kind)
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise DomainError("invalid_value", "Page size must be between 1 and 1000")
        rows = self._db().execute(f"SELECT id,version,body,body_hash FROM {kind.value} WHERE id>? ORDER BY id LIMIT ?", (after or "", limit)).fetchall()
        return tuple(_record(kind, row) for row in rows)

    def insert(self, record: Record) -> None:
        _check_record(record)
        if record.version != 1:
            raise DomainError("version_conflict", "New records start at version 1")
        try:
            self._db().execute(f"INSERT INTO {record.kind.value} VALUES (?,?,?,?)", (record.record_id, record.version, record.value.text, record.value.digest))
        except sqlite3.IntegrityError as exc:
            raise DomainError("version_conflict", "Record already exists") from exc

    def replace(self, record: Record, *, expected_version: int) -> None:
        _check_record(record)
        positive(expected_version, "expected version")
        if record.kind in IMMUTABLE:
            raise DomainError("immutable_record", "Immutable records cannot be replaced")
        if record.version != expected_version + 1:
            raise DomainError("version_conflict", "Replacement must advance exactly one version")
        cursor = self._db().execute(f"UPDATE {record.kind.value} SET version=?,body=?,body_hash=? WHERE id=? AND version=?", (record.version, record.value.text, record.value.digest, record.record_id, expected_version))
        if cursor.rowcount != 1:
            raise DomainError("version_conflict", "Record version has changed")

    def request_result(self, subject_id: str, request_id: str) -> RequestResult | None:
        row = self._db().execute("SELECT digest,response,response_hash FROM request_results WHERE subject=? AND request_id=?", (subject_id, request_id)).fetchone()
        return None if row is None else RequestResult(subject_id, request_id, row[0], _snapshot(row[1], row[2]))

    def record_result(self, result: RequestResult) -> None:
        try:
            self._db().execute("INSERT INTO request_results VALUES (?,?,?,?,?)", (result.subject_id, result.request_id, result.request_digest, result.response.text, result.response.digest))
        except sqlite3.IntegrityError as exc:
            raise DomainError("idempotency_conflict", "Request result already exists") from exc

    def append_event(self, event: Snapshot) -> int:
        body = event.value
        sequence = self._db().execute("SELECT COALESCE(MAX(sequence),0)+1 FROM events").fetchone()[0]
        body["sequence"] = sequence
        stored = Snapshot.of(body)
        self._db().execute("INSERT INTO events(sequence,body,body_hash) VALUES (?,?,?)", (sequence, stored.text, stored.digest))
        return sequence

    def admit_replay(self, *, subject_id: str, session_id: str, opcode: int, nonce: str, expires_at_ms: int) -> None:
        try:
            self._db().execute("INSERT INTO replay_admissions VALUES (?,?,?,?,?)", (subject_id, session_id, opcode, nonce, expires_at_ms))
        except sqlite3.IntegrityError as exc:
            raise DomainError("replay_rejected", "Replay scope was already admitted") from exc


class SQLiteStore:
    def __init__(self, path: str | Path):
        requested = Path(path).absolute()
        if requested.is_symlink():
            raise DomainError("storage_unavailable", "Database path cannot be a symbolic link")
        requested.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = requested.parent.resolve() / requested.name
        self._mutex = threading.RLock()
        self._connection = None
        self._lock_fd = None
        self._transaction_active = False
        try:
            # The owner selects a dedicated directory; do not chmod arbitrary parents.
            if self.path.parent.stat().st_uid != os.getuid() or self.path.parent.stat().st_mode & 0o077:
                raise DomainError("storage_unavailable", "Database directory must be owner-private")
            flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
            self._lock_fd = os.open(str(self.path) + ".writer.lock", flags, 0o600)
            lock_stat = os.fstat(self._lock_fd)
            if not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_nlink != 1 or lock_stat.st_uid != os.getuid() or lock_stat.st_mode & 0o077:
                raise DomainError("storage_unavailable", "Writer lock must be a private regular file with one link")
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise DomainError("storage_unavailable", "Another runtime writer owns this database") from exc
            fd = os.open(self.path, flags, 0o600)
            try:
                file_stat = os.fstat(fd)
                if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1 or file_stat.st_uid != os.getuid() or file_stat.st_mode & 0o077:
                    raise DomainError("storage_unavailable", "Database file must be owner-private")
            finally:
                os.close(fd)
            self._connection = sqlite3.connect(self.path, timeout=5, isolation_level=None, check_same_thread=False)
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA busy_timeout=5000")
            self._migrate()
            self.check_integrity()
        except BaseException:
            self.close()
            raise

    def _db(self):
        if self._connection is None:
            raise DomainError("storage_unavailable", "Store is closed")
        return self._connection

    def _migrate(self):
        db = self._db()
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, SCHEMA_VERSION):
            raise DomainError("incompatible_version", "Database schema is not supported")
        if version == 0:
            db.execute("BEGIN IMMEDIATE")
            try:
                for statement in STATEMENTS:
                    db.execute(statement)
                db.execute("INSERT INTO migration_journal VALUES (?,?)", (SCHEMA_VERSION, SCHEMA_CHECKSUM))
                db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        journal = db.execute("SELECT version,checksum FROM migration_journal ORDER BY version").fetchall()
        if journal != [(SCHEMA_VERSION, SCHEMA_CHECKSUM)]:
            raise DomainError("incompatible_version", "Migration history does not match this runtime")

    @contextmanager
    def transaction(self):
        with self._mutex:
            db = self._db()
            if self._transaction_active:
                raise DomainError("storage_unavailable", "Nested transactions are unsupported")
            tx = SQLiteTransaction(db)
            self._transaction_active = True
            try:
                db.execute("BEGIN IMMEDIATE")
                yield tx
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
            finally:
                tx._active = False
                self._transaction_active = False

    def get(self, kind: RecordKind, record_id: str) -> Record | None:
        with self._mutex:
            return SQLiteTransaction(self._db()).get(kind, record_id)

    def events(self, *, after: int, limit: int) -> tuple[Snapshot, ...]:
        if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 1000:
            raise DomainError("invalid_value", "Invalid event cursor")
        with self._mutex:
            return tuple(_snapshot(row[0], row[1]) for row in self._db().execute("SELECT body,body_hash FROM events WHERE sequence>? ORDER BY sequence LIMIT ?", (after, limit)).fetchall())

    def event_high_watermark(self) -> int:
        with self._mutex:
            return self._db().execute("SELECT COALESCE(MAX(sequence),0) FROM events").fetchone()[0]

    def check_ready(self) -> None:
        with self._mutex:
            row = self._db().execute("SELECT checksum FROM migration_journal WHERE version=?", (SCHEMA_VERSION,)).fetchone()
            if row != (SCHEMA_CHECKSUM,):
                raise DomainError("storage_unavailable", "Storage migration state is unavailable")

    def check_integrity(self) -> None:
        with self._mutex:
            db = self._db()
            if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise DomainError("storage_unavailable", "SQLite integrity check failed")
            for kind in RecordKind:
                for row in db.execute(f"SELECT body,body_hash FROM {kind.value}"):
                    _snapshot(*row)
            for table, fields in (("events", "body,body_hash"), ("request_results", "response,response_hash")):
                for row in db.execute(f"SELECT {fields} FROM {table}"):
                    _snapshot(*row)

    def close(self):
        with self._mutex:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            if self._lock_fd is not None:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                os.close(self._lock_fd)
                self._lock_fd = None
