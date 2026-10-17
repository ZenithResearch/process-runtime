"""Exercise online backup and isolated restore; accepts no operator database path."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, closing, contextmanager
import hashlib
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import uuid
import zipfile


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def require(value, detail):
    if not value:
        raise AssertionError(detail)


def installed_runtime(wheel, expected):
    require(hashlib.sha256(wheel.read_bytes()).hexdigest() == expected, "Wheel digest mismatch")
    distribution = metadata.distribution("process-runtime")
    prefix = Path(sys.prefix).resolve()
    import process_runtime
    import process_runtime_client

    for module in (process_runtime, process_runtime_client):
        require(Path(module.__file__).resolve().is_relative_to(prefix), "Installed imports required")
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.endswith(("/", "/RECORD")):
                continue
            require(not name.startswith("/") and ".." not in Path(name).parts, "Unsafe wheel member")
            if ".data/data/" in name:
                path = prefix / name.split(".data/data/", 1)[1]
            else:
                require(".data/" not in name, "Unsupported wheel layout")
                path = Path(distribution.locate_file(name)).resolve()
            require(path.is_relative_to(prefix) and path.read_bytes() == archive.read(name), "Installed wheel drift")
    return {"package": distribution.metadata["Name"], "version": distribution.version,
            "wheel_sha256": expected, "prefix": str(prefix)}


@contextmanager
def provider(path, clock):
    # This operator belongs to Runtime. Component consumers still use only HTTP/SDK.
    from process_runtime.application import Runtime
    from process_runtime.authority import LocalDevUntrustedVerifier
    from process_runtime.http_api import make_server
    from process_runtime.sqlite_store import SQLiteStore
    from process_runtime_client import LocalDevAuthority, RuntimeClient

    store = SQLiteStore(path)
    runtime = Runtime(store, verifier=LocalDevUntrustedVerifier("backup-fixture"),
                      environment="test", allow_local_dev_untrusted=True, clock=lambda: clock[0])
    server = make_server(runtime)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    local = LocalDevAuthority(environment="test")
    def fixture_evidence(request_body):
        value = json.loads(local(request_body))
        value.update(issued_at_ms=clock[0], expires_at_ms=clock[0] + 60000)
        return canonical(value)
    client = RuntimeClient(f"http://127.0.0.1:{server.server_port}", authority=fixture_evidence)
    try:
        yield runtime, client
    finally:
        server.shutdown()
        server.server_close()
        worker.join(5)
        require(not worker.is_alive(), "Fixture HTTP worker did not stop")
        store.close()


def private_database(path):
    path.parent.mkdir(mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)


def logical_snapshot(path):
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as database:
        require(database.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "Backup integrity failure")
        names = sorted(row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'"))
        tables = {}
        for name in names:
            quoted = '"' + name.replace('"', '""') + '"'
            rows = database.execute("SELECT * FROM " + quoted).fetchall()
            def portable(row):
                return [{"type": type(item).__name__, "value": item.hex() if isinstance(item, bytes) else item} for item in row]
            tables[name] = sorted((portable(row) for row in rows), key=canonical)
        schema = sorted(database.execute("SELECT type,name,tbl_name,sql FROM sqlite_master").fetchall(), key=str)
    return {"schema": schema, "tables": tables}


def backup(source, destination):
    private_database(destination)
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as reader:
        with closing(sqlite3.connect(destination)) as writer:
            reader.backup(writer, pages=1)
    return logical_snapshot(destination)


def run(wheel, expected):
    identity = installed_runtime(wheel, expected)
    from process_runtime_client import RuntimeClientError, command_envelope, exact_retry

    clock = [1_000_000]
    checks = []
    with tempfile.TemporaryDirectory(prefix="runtime-backup-drill-") as temporary:
        root = Path(temporary).resolve()
        source = root / "source" / "runtime.db"
        source.parent.mkdir(mode=0o700)
        backup_path = root / "backup" / "runtime.db"
        restore_path = root / "restored" / "runtime.db"
        # Stacks make the primary stop explicit before the restored owner starts.
        with ExitStack() as primary:
            runtime, client = primary.enter_context(provider(source, clock))
            def command(operation, payload, version=None, request_id=None):
                return client.execute(command_envelope(operation, request_id=request_id or uuid.uuid4().hex,
                                                       expected_version=version, payload=payload))
            def query(operation, payload):
                return client.query({"schema": "runtime.query.v1", "operation": operation, "payload": payload})["data"]
            def step(run_id):
                return query("run.get", {"run_id": run_id})["steps"][0]
            def claim(run_id, lease_ms=120000):
                return command("executor.claim", {"run_id": run_id, "step_id": "compute", "actor_id": "worker", "lease_ms": lease_ms}, step(run_id)["version"])["result"]
            def binding(claimed):
                return {key: claimed[key] for key in ("run_id", "step_id", "attempt_id", "fence")}
            draft = {"schema": "process.draft.v1", "process_id": "backup-development", "inputs": {"number": {"kind": "integer"}},
                     "steps": [{"step_id": "compute", "depends_on": [], "capabilities": ["compute"], "resources": [],
                                "inputs": {"number": {"kind": "integer"}}, "bindings": {"number": {"source": "run_input", "name": "number"}},
                                "outputs": {"answer": {"kind": "integer"}}, "max_attempts": 3}]}
            command("process.draft.put", {"draft": draft, "provenance": {"source_id": "backup-fixture", "media_type": "application/json", "content_hash": hashlib.sha256(canonical(draft)).hexdigest(), "parser": "explicit-json-v1", "uncertainties": []}})
            pin = command("process.publish", {"process_id": draft["process_id"], "draft_revision": 1, "version_id": "backup-v1"}, 1)["result"]["pin"]
            command("actor.register", {"actor_id": "worker", "capabilities": ["compute"], "resources": []})
            for run_id in ("committed", "unknown", "active"):
                command("run.create", {"run_id": run_id, "pin": pin, "inputs": {"number": 7}})
            finished = claim("committed")
            saved = command_envelope("executor.complete", request_id="retained-completion", expected_version=step("committed")["version"], payload={**binding(finished), "outputs": {"answer": 14}})
            result = client.execute(saved)
            output = query("output.get", {key: finished[key] for key in ("run_id", "step_id", "attempt_id")})
            receipt = query("receipt.get", {"receipt_id": output["receipt_id"]})
            uncertain = claim("unknown", lease_ms=1000)
            effect = command("executor.effect.intent", {**binding(uncertain), "effect_name": "synthetic-send", "integration": "fixture", "request_digest": "b" * 64, "provider_idempotent": False}, step("unknown")["version"])["result"]
            command("executor.effect.dispatch", {**binding(uncertain), "effect_id": effect["effect_id"]}, step("unknown")["version"])
            clock[0] += 1000
            runtime.recover()
            require(query("effect.get", {"effect_id": effect["effect_id"]})["state"] == "unknown", "Expected unresolved effect")
            active = claim("active")
            def public_snapshot():
                return {"runs": {name: query("run.get", {"run_id": name}) for name in ("committed", "unknown", "active")},
                        "output": query("output.get", {key: finished[key] for key in ("run_id", "step_id", "attempt_id")}),
                        "receipt": query("receipt.get", {"receipt_id": output["receipt_id"]}),
                        "effect": query("effect.get", {"effect_id": effect["effect_id"]}),
                        "events": query("events.list", {"after": 0, "limit": 100})}
            expected_public = public_snapshot()
            require(expected_public["events"]["high_watermark"] < 100, "Fixture cursor needs pagination")
            source_contents = logical_snapshot(source)
            backup_contents = backup(source, backup_path)
            require(source_contents == backup_contents, "Online backup differs from quiescent source schema/typed rows")
            checks.append({"name": "online-backup-integrity", "tables": len(backup_contents["tables"]), "source_matches_backup": True, "concurrent_mutation_exercised": False, "logical_sha256": hashlib.sha256(canonical(backup_contents)).hexdigest()})
            require(query("run.get", {"run_id": "active"}) == expected_public["runs"]["active"], "Backup disrupted active writer")
            primary.close()
        restored_contents = backup(backup_path, restore_path)
        require(restored_contents == backup_contents, "Restore changed canonical records, replay, results, events or schema")
        checks.append({"name": "exact-logical-restore", "logical_sha256": hashlib.sha256(canonical(restored_contents)).hexdigest()})
        with provider(restore_path, clock) as (runtime, client):
            require(public_snapshot() == expected_public, "Restored public state/output/receipt/cursor differs")
            require(client.execute(exact_retry(saved)) == {**result, "duplicate": True}, "Exact retry lost immutable completion")
            require(query("events.list", {"after": 0, "limit": 100}) == expected_public["events"], "Exact retry repeated completion events")
            changed = json.loads(json.dumps(saved)); changed["payload"]["outputs"]["answer"] = 15
            try:
                client.execute(changed)
            except RuntimeClientError as error:
                require(error.code == "idempotency_conflict", "Changed retry rejection differs")
            else:
                raise AssertionError("Changed saved intent was admitted")
            checks.append({"name": "outputs-receipts-exact-retry", "output_digest": output["output_digest"], "receipt_id": receipt["receipt_id"], "event_cursor": expected_public["events"]["next_cursor"]})
            try:
                claim("active")
            except RuntimeClientError as error:
                require(error.code in ("not_ready", "version_conflict"), "Active owner rejection differs")
            else:
                raise AssertionError("Restored active lease allowed another claim")
            clock[0] += 120000
            runtime.recover()
            next_claim = claim("active")
            require(next_claim["attempt_id"] != active["attempt_id"] and next_claim["fence"] > active["fence"], "Restore recycled Attempt/fence")
            try:
                command("executor.complete", {**binding(active), "outputs": {"answer": 14}}, step("active")["version"])
            except RuntimeClientError as error:
                require(error.code == "stale_fence", "Old owner rejection differs")
            else:
                raise AssertionError("Restored stale owner committed")
            checks.append({"name": "active-lease-and-fence-continuity", "old_fence": active["fence"], "new_fence": next_claim["fence"], "distinct_attempts": True})
            unknown = query("run.get", {"run_id": "unknown"})
            try:
                command("run.retry", {"run_id": "unknown", "step_id": "compute", "reason": "restore cannot resolve provider outcome"}, unknown["version"])
            except RuntimeClientError as error:
                require(error.code == "unknown_outcome", "Unknown recovery rejection differs")
            else:
                raise AssertionError("Restore silently retried unknown effect")
            require(query("effect.get", {"effect_id": effect["effect_id"]})["state"] == "unknown", "Unknown effect history changed")
            checks.append({"name": "unknown-effect-remains-blocked", "external_sends": 0, "rejection": "unknown_outcome"})
    return {"schema": "runtime.backup-restore-drill.v1", "status": "passed", "artifact": identity, "checks": checks,
            "authority_mode": "local_dev_untrusted", "production_qualified": False,
            "limits": ["Disposable fixture stores only; no operator database path is accepted.",
                       "Source owner is live but quiescent during the online copy; concurrent writer mutation is not exercised.",
                       "Primary fixture stops before the restored owner starts; this is no live failover or cutover.",
                       "Only synthetic effect intent is recorded; no provider or external send occurs.",
                       "No native issuer/custody qualification, production RPO/RTO, PostgreSQL or migration claim."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--wheel-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # Create-only evidence preserves prior results, including a failed drill.
    with args.output.open("x") as target:
        try:
            report = run(args.wheel.resolve(), args.wheel_sha256)
        except Exception as error:
            report = {"schema": "runtime.backup-restore-drill.v1", "status": "failed", "error_type": type(error).__name__, "detail": str(error), "production_qualified": False}
        target.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "output": str(args.output)}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
