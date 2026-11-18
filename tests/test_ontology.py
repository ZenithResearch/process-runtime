"""Approved Runtime vocabulary, import closure and application schema boundaries."""

from copy import deepcopy
from importlib.resources import files
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from process_runtime import ontology
from process_runtime.ports import RecordKind

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PARENTS = {
    "runtime:ProcessDefinition": "zn:Artifact",
    "runtime:ProcessVersion": "zn:Artifact",
    "runtime:ProcessRun": "owl:Thing",
    "runtime:StepRun": "owl:Thing",
    "runtime:Attempt": "owl:Thing",
    "runtime:Lease": "owl:Thing",
    "runtime:ActorRegistration": "zn:Artifact",
    "runtime:OutputCommit": "zn:Artifact",
    "runtime:Receipt": "zn:Receipt",
    "runtime:RuntimeEffect": "owl:Thing",
    "runtime:Event": "zn:Event",
}


class OntologyTests(unittest.TestCase):
    def test_all_approved_classes_have_complete_inheritance_paths(self):
        result = ontology.ontology_sources()
        parents = {entry["id"]: entry["parents"] for entry in result["classes"]}
        self.assertEqual(parents, {term: [parent] for term, parent in EXPECTED_PARENTS.items()})
        paths = {entry["id"]: entry["inheritancePaths"] for entry in result["classes"]}
        self.assertEqual(paths["runtime:Receipt"],
                         [["owl:Thing", "zn:Artifact", "zn:Receipt", "runtime:Receipt"]])
        self.assertEqual(paths["runtime:Event"],
                         [["owl:Thing", "zn:Event", "runtime:Event"]])
        for term, paths_for_term in paths.items():
            for path in paths_for_term:
                self.assertEqual(path[0], "owl:Thing")
                self.assertEqual(path[-1], term)
                self.assertEqual(len(path), len(set(path)))

    def test_reused_shared_classes_are_distinct_from_collection_entries(self):
        sources = ontology.ontology_sources()
        mappings = ontology.schema_mappings()["terms"]
        for term, shared in (("RuntimeInbox", "zn:Inbox"), ("RuntimeOutbox", "zn:Outbox")):
            self.assertEqual(sources["sharedReuse"][term]["inheritancePaths"],
                             [["owl:Thing", "zn:Collection", shared]])
            self.assertEqual(mappings[term]["appliesTo"], "logical-collection")
        self.assertEqual(mappings["Artifact"]["appliesTo"], "referenced-artifact")
        self.assertEqual(mappings["ArtifactRef"]["disposition"], "reference")
        self.assertEqual(mappings["ArtifactRef"]["refersTo"], "zn:Artifact")
        self.assertFalse({"runtime:Artifact", "runtime:RuntimeInbox", "runtime:RuntimeOutbox"}
                         & set(EXPECTED_PARENTS))

    def test_every_existing_runtime_term_and_stored_kind_has_a_disposition(self):
        ownership = json.loads((ROOT / "contracts/ownership-v1.json").read_text())
        mappings = ontology.schema_mappings()["terms"]
        self.assertEqual(set(mappings), set(ownership["owners"]["process-runtime"]))
        stored = [entry["recordKind"] for entry in mappings.values() if "recordKind" in entry]
        self.assertEqual(set(stored), {entry.value for entry in RecordKind})
        self.assertEqual(len(stored), len(set(stored)))
        for term in ("CompiledProcess", "Actor", "ProcessPin", "ArtifactRef", "AttemptSpan"):
            self.assertNotEqual(mappings[term]["disposition"], "class")

    def test_event_stream_describes_occurrences_and_receipt_retains_its_record_meaning(self):
        mappings = ontology.schema_mappings()["terms"]
        self.assertEqual(mappings["RuntimeEvent"]["disposition"], "description")
        self.assertEqual(mappings["RuntimeEvent"]["describes"], "runtime:Event")
        self.assertEqual(mappings["Receipt"]["class"], "runtime:Receipt")
        self.assertEqual(mappings["Actor"]["disposition"], "structure")
        self.assertEqual(mappings["ActorRegistration"]["class"], "runtime:ActorRegistration")

    def test_schema_references_resolve_to_existing_public_sdk_definitions(self):
        schema = json.loads(files("process_runtime_client").joinpath("runtime-v1.schema.json").read_bytes())
        for term, mapping in ontology.schema_mappings()["terms"].items():
            if "schemaRef" in mapping:
                document, pointer = mapping["schemaRef"].split("#", 1)
                self.assertEqual(document, schema["$id"], term)
                value = schema
                for field in pointer.lstrip("/").split("/"):
                    value = value[field]
                self.assertIsInstance(value, dict, term)
        self.assertEqual(schema["$defs"]["receipt"]["properties"]["signature"], {"type": "null"})

    def test_process_version_relationships_have_the_reviewed_domains_and_ranges(self):
        nodes = {entry["@id"]: entry for entry in ontology.ontology_document()["@graph"]}
        relation = nodes["runtime:versionOf"]
        self.assertEqual((relation["@type"], relation["domain"], relation["range"]),
                         ("owl:ObjectProperty", "runtime:ProcessVersion", "runtime:ProcessDefinition"))
        execution = nodes["runtime:executesVersion"]
        self.assertEqual((execution["domain"], execution["range"]),
                         ("runtime:ProcessRun", "runtime:ProcessVersion"))

    def test_domain_is_an_identified_core_domain_with_module_and_vocabulary_references(self):
        result = ontology.ontology_sources()
        domain = result["domain"]
        nodes = {entry["@id"]: entry for entry in ontology.ontology_document()["@graph"]}
        self.assertIn("zn:Domain", nodes[domain["id"]]["@type"])
        self.assertEqual(domain["type"], "zn:Domain")
        self.assertEqual(domain["sourceModuleRef"], result["extension"]["versionIri"])
        self.assertEqual(domain["vocabularyRef"], result["extension"]["ontologyId"])
        self.assertEqual(domain["key"], "runtime/process-runtime")

    def test_ontology_imports_and_schema_resolution_work_offline(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network prohibited")), \
             patch.object(socket, "create_connection", side_effect=AssertionError("network prohibited")):
            result = ontology.ontology_sources()
        self.assertTrue(result["closureVerified"])
        self.assertEqual(result["adoptedZenith"]["gitCommit"],
                         "4a5e54d744c0b1ed0e4dc5750ad98eb52dd11bc2")
        self.assertEqual(len(result["importClosure"]), 3)
        self.assertEqual(set(ontology.ontology_document()["@graph"][0]["imports"]), {
            "https://zenith-research.ca/ontology/normalized/v0.1.0/modules/core.jsonld",
            "https://zenith-research.ca/ontology/normalized/v0.1.0/modules/messaging.jsonld",
        })

    def test_diagnostic_cli_works_from_an_empty_directory_without_a_database(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, "-I", "-m", "process_runtime.ontology",
                                     "--format", "sources-v1"],
                                    cwd=directory, capture_output=True, text=True, check=True, timeout=15)
            self.assertTrue(json.loads(result.stdout)["closureVerified"])
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_returned_documents_do_not_mutate_the_packaged_module(self):
        document = ontology.ontology_document()
        original = deepcopy(document)
        document["@graph"].clear()
        self.assertEqual(ontology.ontology_document(), original)

    def copy_resources(self, directory):
        root = Path(directory)
        shutil.copytree(files("process_runtime").joinpath("ontology_resources"),
                        root / "ontology_resources")
        return root

    def update_digest(self, root, name):
        assets = root / "ontology_resources"
        manifest = json.loads((assets / "manifest.json").read_text())
        contents = (assets / name).read_bytes()
        entry, = (entry for entry in manifest["files"] if entry["path"] == name)
        entry.update(bytes=len(contents), sha256=hashlib.sha256(contents).hexdigest())
        (assets / "manifest.json").write_text(json.dumps(manifest))

    def test_tampered_assets_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_resources(directory)
            (root / "ontology_resources/mappings.json").write_text("{}")
            with patch.object(ontology, "files", return_value=root):
                with self.assertRaisesRegex(ValueError, "file integrity mismatch"):
                    ontology.ontology_sources()

    def test_missing_import_is_rejected_without_network_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_resources(directory)
            path = root / "ontology_resources/ontology.jsonld"
            data = json.loads(path.read_text())
            data["@graph"][0]["imports"].append("https://unconfigured.example/ontology.jsonld")
            path.write_text(json.dumps(data))
            self.update_digest(root, "ontology.jsonld")
            with patch.object(ontology, "files", return_value=root), \
                 patch.object(socket, "socket", side_effect=AssertionError("network prohibited")):
                with self.assertRaisesRegex(ValueError, "absent from the packaged closure"):
                    ontology.ontology_sources()

    def test_changed_shared_class_cannot_be_admitted_as_the_pinned_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_resources(directory)
            name = "zenith-v0.1.0/modules/core.jsonld"
            path = root / "ontology_resources" / name
            data = json.loads(path.read_text())
            data["@graph"].pop()
            path.write_text(json.dumps(data))
            self.update_digest(root, name)
            with patch.object(ontology, "files", return_value=root):
                with self.assertRaisesRegex(ValueError, "Pinned Zenith file integrity mismatch"):
                    ontology.ontology_sources()

    def test_context_rebinding_cannot_change_shared_term_or_inheritance_meaning(self):
        for alias, replacement in (("zn", "https://unconfigured.example/terms/"),
                                   ("subClassOf", {"@id": "rdfs:seeAlso", "@type": "@id"})):
            with self.subTest(alias=alias), tempfile.TemporaryDirectory() as directory:
                root = self.copy_resources(directory)
                path = root / "ontology_resources/ontology.jsonld"
                data = json.loads(path.read_text())
                data["@context"][alias] = replacement
                path.write_text(json.dumps(data))
                self.update_digest(root, "ontology.jsonld")
                with patch.object(ontology, "files", return_value=root):
                    with self.assertRaisesRegex(ValueError, "Vocabulary context changes"):
                        ontology.ontology_sources()
