from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import json
import unittest

from process_runtime.authoring import import_document, render_markdown
from process_runtime.compiler import compile_definition, compile_draft, publish, validate_values
from process_runtime.domain import DomainError, ProcessDefinition, ProcessPin, ProcessRun, Snapshot

FIXTURES = Path(__file__).parent / "fixtures" / "process-publication"
STRING = {"kind": "string"}
INTEGER = {"kind": "integer"}
NUMBER = {"kind": "number"}


def definition(draft, revision=1, uncertainties=None):
    return ProcessDefinition(draft["process_id"], revision, Snapshot.of(draft), Snapshot.of({
        "source_id": "review-source", "media_type": "application/json", "content_hash": "a" * 64,
        "parser": "explicit-json-v1", "uncertainties": uncertainties or [],
    }))


class CompilerTests(unittest.TestCase):
    def setUp(self):
        self.draft = json.loads((FIXTURES / "personal-review.draft.json").read_text())

    def test_golden_compilation_is_exact_and_storage_independent(self):
        compiled = compile_draft(self.draft)
        golden = json.loads((FIXTURES / "personal-review.compiled.json").read_text())
        self.assertEqual(compiled.snapshot.value, golden["snapshot"])
        self.assertEqual(compiled.compilation_hash, golden["compilation_hash"])
        self.assertEqual(compiled.snapshot.digest, compiled.compilation_hash)
        self.assertEqual(compiled.snapshot.value["roots"], ["capture"])
        self.assertEqual(compiled.snapshot.value["topological_order"], ["capture", "review", "record"])
        self.assertEqual(compiled.snapshot.value["ancestors"]["record"], ["capture", "review"])
        run = ProcessRun("personal-run", ProcessPin.of(publish(definition(self.draft),
            expected_revision=1, version_id="personal-v1", ordinal=1, published_at_ms=1000)), Snapshot.of({"notes": "today"}))
        self.assertIsNone(run.source_ref)

    def test_order_normalization_produces_same_hash_but_preserves_literal_array_order(self):
        changed = deepcopy(self.draft)
        changed["steps"].reverse()
        for step in changed["steps"]:
            for field in ("capabilities", "resources", "depends_on"):
                step[field].reverse()
            step["inputs"] = dict(reversed(list(step["inputs"].items())))
            for spec in step["outputs"].values():
                if spec["kind"] == "object":
                    spec["required"].reverse()
        self.assertEqual(compile_draft(self.draft), compile_draft(changed))
        changed = deepcopy(self.draft)
        changed["steps"][1]["inputs"]["labels"] = {"kind": "array", "items": STRING}
        changed["steps"][1]["bindings"]["labels"] = {"source": "literal", "value": ["first", "second"]}
        original = compile_draft(changed)
        changed["steps"][1]["bindings"]["labels"]["value"].reverse()
        self.assertNotEqual(original.compilation_hash, compile_draft(changed).compilation_hash)

    def test_missing_duplicate_self_and_cyclic_edges_are_rejected(self):
        mutations = [
            lambda d: d["steps"].append(deepcopy(d["steps"][0])),
            lambda d: d["steps"][1].update(depends_on=["missing"]),
            lambda d: d["steps"][1].update(depends_on=["review"]),
            lambda d: d["steps"][0].update(depends_on=["record"]),
        ]
        for mutate in mutations:
            draft = deepcopy(self.draft); mutate(draft)
            with self.subTest(draft=draft), self.assertRaises(DomainError) as raised:
                compile_draft(draft)
            self.assertEqual(raised.exception.code, "invalid_dag")

    def test_bindings_require_exact_inputs_existing_ports_and_declared_ancestry(self):
        mutations = [
            lambda d: d["steps"][0]["bindings"].clear(),
            lambda d: d["steps"][0]["bindings"].update(extra={"source": "literal", "value": "x"}),
            lambda d: d["steps"][0]["bindings"]["notes"].update(name="missing"),
            lambda d: d["steps"][1]["bindings"]["brief"].update(name="missing"),
            lambda d: d["steps"][1]["bindings"]["brief"].update(step_id="record"),
            lambda d: d["steps"][1]["bindings"]["brief"].update(step_id="review"),
            lambda d: d["steps"][1].update(depends_on=[]),
        ]
        for mutate in mutations:
            draft = deepcopy(self.draft); mutate(draft)
            with self.subTest(mutate=mutate), self.assertRaises(DomainError) as raised:
                compile_draft(draft)
            self.assertEqual(raised.exception.code, "invalid_dag")

    def test_transitive_bindings_and_multiple_deterministic_roots(self):
        # record consumes capture.brief through review, already a declared ancestor.
        self.assertIn("capture", compile_draft(self.draft).snapshot.value["ancestors"]["record"])
        draft = deepcopy(self.draft)
        root = deepcopy(draft["steps"][0]); root["step_id"] = "a-independent"
        draft["steps"].append(root)
        compiled = compile_draft(draft).snapshot.value
        self.assertEqual(compiled["roots"], ["a-independent", "capture"])
        self.assertEqual(compiled["topological_order"][:2], ["a-independent", "capture"])

    def test_type_compatibility_is_directional_and_booleans_are_not_integers(self):
        for source, target, allowed in [(INTEGER, NUMBER, True), (NUMBER, INTEGER, False), (STRING, NUMBER, False)]:
            draft = deepcopy(self.draft)
            draft["inputs"]["notes"] = source
            draft["steps"][0]["inputs"]["notes"] = target
            if allowed:
                compile_draft(draft)
            else:
                with self.assertRaises(DomainError) as raised:
                    compile_draft(draft)
                self.assertEqual(raised.exception.code, "type_mismatch")
        draft = deepcopy(self.draft)
        draft["steps"][1]["bindings"]["maximum"]["value"] = True
        with self.assertRaises(DomainError):
            compile_draft(draft)

    def test_recursive_object_assignment_preserves_required_guarantees_and_closed_shape(self):
        source = {"kind": "object", "properties": {"items": {"kind": "array", "items": INTEGER}}, "required": ["items"]}
        target = {"kind": "object", "properties": {"items": {"kind": "array", "items": NUMBER}, "note": STRING}, "required": ["items"]}
        draft = deepcopy(self.draft)
        draft["inputs"]["notes"] = source; draft["steps"][0]["inputs"]["notes"] = target
        compile_draft(draft)
        source["required"] = []
        with self.assertRaises(DomainError):
            compile_draft(draft)
        source["required"] = ["items"]
        source["properties"]["undeclared"] = STRING
        with self.assertRaises(DomainError):
            compile_draft(draft)

    def test_malformed_type_required_property_and_identifier_are_rejected(self):
        for spec in [
            {"kind": "object", "properties": {}, "required": ["missing"]},
            {"kind": "object", "properties": {"bad/name": STRING}, "required": []},
            {"kind": "array", "items": {"kind": "unknown"}},
        ]:
            draft = deepcopy(self.draft); draft["inputs"]["notes"] = spec
            with self.subTest(spec=spec), self.assertRaises(DomainError):
                compile_draft(draft)

    def test_values_enforce_exact_ports_recursive_shapes_and_artifact_references(self):
        ports = {"list": {"kind": "array", "items": INTEGER}, "artifact": {"kind": "artifact"},
                 "record": {"kind": "object", "properties": {"name": STRING, "count": INTEGER}, "required": ["name"]}}
        values = {"list": [1, 2], "artifact": {"content_hash": "a" * 64, "byte_length": 2, "media_type": "text/plain"}, "record": {"name": "review"}}
        self.assertEqual(validate_values(values, ports).value, values)
        mutations = [lambda v: v.update(extra=1), lambda v: v.pop("list"),
                     lambda v: v["list"].append(True), lambda v: v["list"].append(1.0),
                     lambda v: v["record"].update(extra=1), lambda v: v["record"].clear(),
                     lambda v: v["artifact"].update(byte_length=True),
                     lambda v: v["artifact"].update(content_hash="0"),
                     lambda v: v["artifact"].update(secret="no")]
        for mutate in mutations:
            changed = deepcopy(values); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(DomainError):
                validate_values(changed, ports)

    def test_hash_binds_execution_structure_capabilities_resources_and_retry_policy(self):
        original = compile_draft(self.draft).compilation_hash
        for field, value in [("capabilities", ["other"]), ("resources", ["other"]), ("max_attempts", 2), ("title", "Changed title")]:
            draft = deepcopy(self.draft); draft["steps"][0][field] = value
            self.assertNotEqual(original, compile_draft(draft).compilation_hash)
        draft = deepcopy(self.draft); draft["steps"][0]["max_attempts"] = 1.0
        with self.assertRaises(DomainError):
            compile_draft(draft)

    def test_publication_is_revision_checked_and_never_repins_existing_values(self):
        source = definition(self.draft, revision=4)
        compiled = compile_definition(source)
        version = publish(source, expected_revision=4, version_id="review-v4", ordinal=4, published_at_ms=1000)
        pin = ProcessPin.of(version)
        self.assertEqual(compiled.source_revision, 4)
        self.assertEqual(compiled.source_draft, source.draft)
        self.assertEqual(compiled.provenance, source.provenance)
        self.assertEqual(version.source_revision, 4)
        changed = deepcopy(self.draft); changed["steps"][0]["max_attempts"] = 2
        revised = source.revise(expected_revision=4, draft=Snapshot.of(changed), provenance=source.provenance)
        replacement = publish(revised, expected_revision=5, version_id="review-v5", ordinal=5, published_at_ms=1100)
        self.assertNotEqual(pin.compilation_hash, replacement.compiled.compilation_hash)
        self.assertEqual(version.compiled, compiled.compiled)
        with self.assertRaises(FrozenInstanceError):
            version.ordinal = 8
        for expected in (3, 5, True, 4.0):
            with self.subTest(expected=expected), self.assertRaises(DomainError):
                publish(source, expected_revision=expected, version_id="bad", ordinal=1, published_at_ms=1000)

    def test_uncertainty_process_mismatch_and_malformed_provenance_block_publication(self):
        source = definition(self.draft)
        # Identity mismatch is rejected at value construction, before publication.
        with self.assertRaises(DomainError) as caught:
            replace(source, process_id="other")
        self.assertEqual(caught.exception.code, "process_mismatch")
        bad = [definition(self.draft, uncertainties=["Ambiguous ownership"]),
               replace(source, provenance=Snapshot.of({}))]
        for item in bad:
            with self.subTest(item=item), self.assertRaises(DomainError):
                publish(item, expected_revision=1, version_id="review-v1", ordinal=1, published_at_ms=1000)

    def test_input_size_depth_nonfinite_and_unicode_are_bounded(self):
        bad = deepcopy(self.draft); bad["title"] = "\ud800"
        with self.assertRaises(DomainError):
            compile_draft(bad)
        for value in (float("nan"), "x" * 1_048_577):
            with self.assertRaises(DomainError):
                validate_values({"value": value}, {"value": STRING})
        value = None
        for _ in range(60):
            value = [value]
        with self.assertRaises(DomainError):
            validate_values({"value": value}, {"value": STRING})

    def test_final_newline_is_not_a_valid_identifier_or_resource(self):
        for field in ("step_id", "capabilities", "resources"):
            draft = deepcopy(self.draft)
            draft["steps"][0][field] = "capture\n" if field == "step_id" else ["name\n"]
            with self.subTest(field=field), self.assertRaises(DomainError):
                compile_draft(draft)
        with self.assertRaises(DomainError):
            validate_values({"value\n": "x"}, {"value\n": STRING})


class AuthoringTests(unittest.TestCase):
    def setUp(self):
        self.content = (FIXTURES / "personal-review.draft.json").read_bytes()
        self.draft = json.loads(self.content)

    def test_json_markdown_and_text_import_preserve_explicit_source_and_provenance(self):
        markdown = render_markdown(self.draft).encode()
        results = [import_document(self.content, source_id="json-upload", media_type="application/json"),
                   import_document(markdown, source_id="markdown-upload", media_type="text/markdown"),
                   import_document(markdown, source_id="text-upload", media_type="text/plain")]
        for result in results:
            self.assertTrue(result.accepted)
            self.assertEqual(result.draft.value, self.draft)
            self.assertEqual(result.uncertainties, ())
            self.assertEqual(result.definition(revision=1).draft, result.draft)
        self.assertNotEqual(results[0].provenance.value["content_hash"], results[1].provenance.value["content_hash"])
        self.assertEqual(compile_draft(results[0].draft), compile_draft(results[1].draft))

    def test_ambiguous_prose_multiple_blocks_and_unclosed_blocks_never_infer_steps(self):
        markdown = render_markdown(self.draft).encode()
        for content in [b"Review things, then maybe publish after checking with somebody.",
                        markdown + markdown, markdown.rsplit(b"```", 1)[0],
                        b"````example\n" + markdown + b"\n````\n"]:
            result = import_document(content, source_id="ambiguous", media_type="text/markdown")
            self.assertFalse(result.accepted)
            self.assertIsNone(result.draft)
            self.assertTrue(result.uncertainties)
            with self.assertRaises(DomainError):
                result.definition(revision=1)

    def test_duplicate_fields_unknown_structure_and_invalid_utf8_surface_uncertainty(self):
        for content in [b'{"schema":"process.draft.v1","schema":"other"}', b'{"steps":[]}', b'NaN', b'\xff',
                        self.content.replace(b'"max_attempts": 1', b'"max_attempts": true')]:
            result = import_document(content, source_id="bad", media_type="application/json")
            self.assertFalse(result.accepted)
            self.assertTrue(result.uncertainties)

    def test_only_bounded_declared_upload_formats_are_supported(self):
        for content, media_type in [(self.content, "application/pdf"), (b"x" * 1_048_577, "text/plain"),
                                    ("not-bytes", "text/plain")]:
            with self.subTest(media_type=media_type), self.assertRaises(DomainError):
                import_document(content, source_id="source", media_type=media_type)


if __name__ == "__main__":
    unittest.main()
