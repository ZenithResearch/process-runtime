from copy import deepcopy
from pathlib import Path
import json
import unittest

from jsonschema import Draft202012Validator
from process_runtime.contracts import COMMANDS, QUERIES, command_digest, schema_bundle, validate
from process_runtime.domain import DomainError

ROOT = Path(__file__).resolve().parents[1]


class PublicContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = json.loads((ROOT / "contracts" / "consumer-fixtures-v1.json").read_text())

    def test_schema_and_export_are_valid_and_current(self):
        schema = schema_bundle()
        Draft202012Validator.check_schema(schema)
        self.assertEqual(schema, json.loads((ROOT / "contracts" / "runtime-v1.schema.json").read_text()))

    def test_fixture_coverage_includes_every_mvp_command_and_query(self):
        self.assertEqual(set(COMMANDS), {item["operation"] for item in self.fixtures["commands"]})
        self.assertEqual(set(QUERIES), {item["operation"] for item in self.fixtures["queries"]})
        for kind, items in (("command", self.fixtures["commands"]), ("query", self.fixtures["queries"])):
            for envelope in items:
                with self.subTest(kind=kind, operation=envelope["operation"]):
                    validate(envelope, kind)

    def test_consumer_acknowledgement_and_event_use_the_command_resource(self):
        from process_runtime_client import resource_for
        result = self.fixtures["result"]
        command = next(item for item in self.fixtures["commands"]
                       if item["operation"] == result["operation"])
        self.assertEqual(result["resource"], resource_for(command))
        self.assertEqual(self.fixtures["event"]["resource"], resource_for(command))
        for kind in ("command", "query"):
            items = self.fixtures["commands" if kind == "command" else "queries"]
            for item in items:
                for mutation in (lambda value: value.update(unknown=True),
                                 lambda value: value["payload"].update(unknown=True),
                                 lambda value: value.update(schema="runtime.unsupported.v9")):
                    changed = deepcopy(item)
                    mutation(changed)
                    with self.subTest(kind=kind, operation=item["operation"]), self.assertRaises(DomainError):
                        validate(changed, kind)

    def test_envelopes_are_closed_at_every_operation_boundary(self):
        for envelope in self.fixtures["commands"]:
            for mutate in (lambda e: e.update(authority={"public_key": "caller-supplied"}),
                           lambda e: e["payload"].update(unrecognized_field=True),
                           lambda e: e.update(schema="runtime.command.v9"),
                           lambda e: e.update(expected_version=True),
                           lambda e: e.pop("resource")):
                changed = deepcopy(envelope)
                mutate(changed)
                with self.subTest(operation=envelope["operation"], changed=changed.keys()), self.assertRaises(DomainError):
                    validate(changed, "command")

    def test_mutations_require_concurrency_precondition(self):
        for item in self.fixtures["commands"]:
            if item["operation"] not in ("process.draft.put", "run.create", "artifact.put", "actor.register", "handoff.consume"):
                changed = {**item, "expected_version": None}
                with self.subTest(operation=item["operation"]), self.assertRaises(DomainError):
                    validate(changed, "command")

    def test_request_digest_binds_every_command_field_and_survives_key_order(self):
        envelope = next(item for item in self.fixtures["commands"] if item["operation"] == "executor.complete")
        original = command_digest(envelope)
        self.assertEqual(original, command_digest(dict(reversed(list(envelope.items())))))
        for field, value in (("fence", 2), ("attempt_id", "different-attempt"), ("run_id", "different-run"), ("outputs", {"passed": False})):
            changed = deepcopy(envelope)
            changed["payload"][field] = value
            self.assertNotEqual(original, command_digest(changed))
        changed = {**envelope, "expected_version": 2}
        self.assertNotEqual(original, command_digest(changed))

    def test_invalid_types_limits_and_missing_executor_binding_fail(self):
        heartbeat = next(item for item in self.fixtures["commands"] if item["operation"] == "executor.heartbeat")
        for field, value in (("fence", 0), ("fence", True), ("lease_ms", 0), ("lease_ms", 300001), ("attempt_id", "bad/id")):
            changed = deepcopy(heartbeat)
            changed["payload"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(DomainError):
                validate(changed, "command")
        for query in self.fixtures["queries"]:
            if "limit" in query["payload"]:
                changed = deepcopy(query)
                changed["payload"]["limit"] = 101
                with self.assertRaises(DomainError):
                    validate(changed, "query")

    def test_unknown_operations_and_payload_credentials_are_not_admitted(self):
        envelope = deepcopy(self.fixtures["commands"][0])
        envelope["operation"] = "database.execute"
        with self.assertRaises(DomainError):
            validate(envelope, "command")
        message = None
        envelope = deepcopy(self.fixtures["commands"][0])
        envelope["payload"]["bearer"] = "secret-marker-do-not-log"
        try:
            validate(envelope, "command")
        except DomainError as exc:
            message = str(exc)
        self.assertIsNotNone(message)
        self.assertNotIn("secret-marker", message)

    def test_event_result_error_and_receipt_envelopes_are_closed(self):
        for kind in ("event", "result", "error", "receipt"):
            envelope = deepcopy(self.fixtures[kind])
            validate(envelope, kind)
            envelope["unknown"] = True
            with self.subTest(kind=kind), self.assertRaises(DomainError):
                validate(envelope, kind)

class OwnershipBoundaryTests(unittest.TestCase):
    def test_every_declared_state_object_has_one_owner_and_references_resolve(self):
        inventory = json.loads((ROOT / "contracts" / "ownership-v1.json").read_text())
        owners = {}
        for owner, objects in inventory["owners"].items():
            for name in objects:
                self.assertNotIn(name, owners, f"Duplicate canonical aggregate {name}")
                owners[name] = owner
        for reference in inventory["references"]:
            self.assertIn(reference["from"], owners)
            if reference["to"] != "AuthenticatedSubject":
                self.assertEqual(owners[reference["to"]], reference["owner"])
        for name in inventory["forbidden_hub_aggregates"]:
            self.assertNotIn(name, inventory["owners"]["hub"])

    def test_all_domain_values_and_persisted_kinds_have_a_canonical_runtime_owner(self):
        import dataclasses
        from process_runtime import domain
        from process_runtime.ports import RecordKind
        inventory = json.loads((ROOT / "contracts" / "ownership-v1.json").read_text())
        runtime_owned = set(inventory["owners"]["process-runtime"])
        state_values = {name for name, value in vars(domain).items()
                        if isinstance(value, type) and dataclasses.is_dataclass(value)
                        and value.__module__ == domain.__name__ and name != "Snapshot"}
        self.assertLessEqual(state_values, runtime_owned)
        self.assertEqual(set(inventory["runtime_records"]), {kind.value for kind in RecordKind})
        self.assertLessEqual(set(inventory["runtime_records"].values()), runtime_owned)
        # Runtime execution decisions and Frank's provider journal are separate records.
        self.assertEqual(inventory["runtime_records"]["external_effect"], "RuntimeEffect")
        self.assertIn("ExternalEffectJournal", inventory["owners"]["frank"])
        self.assertNotIn("RuntimeEffect", inventory["owners"]["frank"])
        self.assertEqual(set(inventory["query_state_objects"]), set(QUERIES))
        for operation, objects in inventory["query_state_objects"].items():
            self.assertTrue(objects, operation)
            self.assertLessEqual(set(objects), runtime_owned, operation)

    def test_domain_imports_cannot_reach_storage_transport_or_service_aggregates(self):
        import ast
        source = (ROOT / "src" / "process_runtime" / "domain.py").read_text()
        tree = ast.parse(source)
        forbidden = {"sqlite3", "psycopg", "neo4j", "requests", "httpx", "service_management", "frank"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn(alias.name.split('.')[0], forbidden)
            elif isinstance(node, ast.ImportFrom):
                self.assertNotIn((node.module or '').split('.')[0], forbidden)
        from process_runtime.ports import RecordKind
        self.assertFalse(any(kind.value in {"case", "service_request", "case_run_binding"} for kind in RecordKind))


class IntegerBoundaryTests(unittest.TestCase):
    def test_integer_fields_reject_float_and_boolean(self):
        from process_runtime.contracts import validate
        from process_runtime.domain import DomainError
        for value in (1.0, True):
            with self.assertRaises(DomainError):
                validate({"schema":"runtime.query.v1","operation":"events.list","payload":{"after":value,"limit":1}}, "query")

if __name__ == "__main__":
    unittest.main()
