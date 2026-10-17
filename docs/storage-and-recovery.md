# Persistence and recovery

The application owns `RuntimeStore` and `Transaction` in `ports.py`. The domain imports no database, transport, clock or credential API. SQLite is the first adapter, with one admitted writer process per database, serialized transactions inside that process, `BEGIN IMMEDIATE`, WAL and `synchronous=FULL`.

Schema 1 creates separate records for drafts, published versions, runs, steps, Attempts, leases, Actors, immutable outputs, artifacts, receipts, effects, inbox and outbox. The migration journal checksums deterministic DDL; unknown versions and mismatched history fail closed. Immutable-record triggers also reject direct adapter updates/deletes. Every stored body has a canonical SHA-256 integrity check. Startup verifies database integrity and retained bodies. These hashes detect corruption; they are not cryptographic protection against a privileged database editor.

A mutation commits its compare-and-swap changes, replay admission, immutable outputs/receipts, audit event, wake-up outbox and exact request result in one transaction. Lost responses are retried with the original operation, request ID, payload and expected version. A fresh narrowly bound authority proof may accompany the identical command. Reusing the request ID with changed content fails. The current authority is verified after writer admission, including on duplicate reads; a queued request cannot use a stale pre-lock clock or cached permission decision.

A lease is valid only for its run, step, Attempt, Actor, fence and expiry. Heartbeat and effect calls advance the step version. A retry claims a new Attempt and larger fence. Recovery records a terminal expiry receipt. Undispatched or confirmed-failed effects can permit retry; dispatched, acknowledged, unknown, or already successful effects prevent an implicit repeat. Reconciliation of a failed effect may permit an explicitly requested new Attempt. Successful effects with lost outputs remain blocked pending a future explicit carry-forward recovery contract; the MVP does not guess output values or repeat the effect.

Outbox events contain only cursor hints. A send may be repeated after a crash between notification and marking delivery; consumers query canonical events and deduplicate sequence/event identity. No bus acknowledgement changes execution state. Inbox identities bind source/event and source/idempotency key to the exact handoff payload and generated run.

## SQLite operating ceiling

This adapter supports one runtime writer on an owner-private local filesystem. Network/shared filesystems, multiple active runtime writers, active/active deployment and copying live database files independently of their WAL are unsupported. Keep storage inside the runtime component. No benchmark has established a numeric throughput ceiling. Monitor command latency, writer queue time, database/WAL growth and recovery duration before setting workload limits.

Use SQLite's online backup facility or stop the runtime cleanly and preserve the database with its recovery state. Restore only into a separate private directory, run integrity checks, then exercise exact request replay and output/receipt queries. Never clear lock or WAL files to force startup. Automatic pruning of requests, replay admissions, receipts and events is intentionally absent: retention requires a policy that preserves replay and reconciliation guarantees.

## Testable PostgreSQL migration boundary

`tests/test_storage.py::PersistenceContract` is adapter-independent and is the required conformance suite for a PostgreSQL adapter. It asserts atomic record/event/result/replay rollback, immutable commits, compare-and-swap, concurrent claim exclusion, ordered cursors and transaction lifetime. PostgreSQL must additionally run the runtime application/HTTP/crash suites against its adapter; passing a mock or SQLite suite alone does not qualify PostgreSQL.

A PostgreSQL implementation should use its own migrations and explicit transactions, unique keys for request/inbox/replay identities, conditional updates with affected-row checks, and row or transaction-level serialization of claims. Event sequence allocation and durable results must commit atomically; a sequence gap must be explicitly described by the cursor contract rather than mistaken for missing delivery. SQL, connection pools, isolation configuration and retryable serialization errors remain adapter details.

Migration is warranted when the single writer, local disk capacity or measured recovery target is inadequate, or when operational requirements need a managed database. Before cutover: stop admission, drain or preserve active leases and unknown effects, export immutable identities and canonical bytes, import without repinning or renumbering, compare counts/hashes/cursors, run conformance and crash tests, then verify exact retry results. Retain the original store and route existing runs to one authoritative owner throughout rollback. No PostgreSQL adapter or production migration is claimed by this release.

## Installed crash-test mode

Set `PROCESS_RUNTIME_CRASH_INSTALLED=1` when running the retained tests against an
installed wheel. Crash children then import only explicit test fixtures through
`PYTHONPATH` and assert that `process_runtime` resolves within their installation
prefix. The component source directory is excluded. Omitting the flag retains the
existing source test mode. Use an isolated installed Python, `-I`, explicit pinned
native helper and freshly generated public native fixtures for a full artifact
check; fixture availability and skip counts remain explicit evidence.

## Disposable installed backup/restore drill

Run the Runtime-owned drill with an isolated Python that has already installed the exact reviewed Runtime wheel and dependencies:

```sh
/path/to/installed/bin/python -I scripts/verify_backup_restore.py \
  --wheel /path/to/process_runtime-0.1.0-py3-none-any.whl \
  --wheel-sha256 REVIEWED_WHEEL_SHA256 \
  --output /example/tmp/backup-restore-new.json
```

The command verifies the wheel digest and installed bytes before creating fixture stores. It accepts no operator database path. It uses SQLite online backup while a disposable Runtime HTTP owner is live, restores into a separate private directory, and stops the original owner before starting the restored one. The source owner is live but quiescent during copying; this drill does not claim concurrent-write coverage. The drill checks integrity and exact source → backup → restore schema/typed-row snapshots across all tables, then reads the retained process pins, outputs, receipts, effects and event cursor through the installed public HTTP SDK. Exact saved completion retries remain duplicate reads; changed retries deny. Active leases retain ownership until expiry; recovery creates a different Attempt and larger fence, and the old owner cannot commit. An unresolved dispatched effect remains unknown and blocks retry, with zero external sends.

Reports are create-only and declare `local_dev_untrusted` test authority. Fixture time and its explicitly untrusted proof times advance together; no production clock or authority adapter is modified. This is isolated restore evidence, not live failover/cutover, native custody qualification, a measured production RPO/RTO, PostgreSQL implementation or external-effect reconciliation. Run only against installed artifacts; component source directories are not added to the import path.
