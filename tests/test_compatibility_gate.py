"""Mutate disposable producers, then run the exact prepublication CLI."""

from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CompatibilityGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="runtime-compatibility-negative-"
        )
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("src", "scripts", "contracts", "resources", "tests"):
            shutil.copytree(
                ROOT / name,
                self.root / name,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )

    def gate(self):
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(self.root / "scripts/check_compatibility.py"),
                "--root",
                str(self.root),
            ],
            env={
                key: value for key, value in os.environ.items() if key != "PYTHONPATH"
            },
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertTrue(result.stdout.strip(), result.stderr)
        return result, json.loads(result.stdout)

    def test_current_provider_consumer_and_all_generated_outputs_pass(self):
        result, report = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["status"], "compatible")
        self.assertEqual(len(report["generated"]), 12)
        self.assertGreater(report["http_tests"], 0)

    def test_incompatible_provider_schema_fails_even_after_regeneration(self):
        source = self.root / "src/process_runtime/contracts.py"
        source.write_text(
            source.read_text()
            + '\nCOMMANDS["actor.advertise"]["required"].append("new_required_field")\n'
        )
        script = self.root / "scripts/check_compatibility.py"
        regenerate = subprocess.run(
            [
                sys.executable,
                "-I",
                str(script),
                "--root",
                str(self.root),
                "--emit-generated",
                str(self.root),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(regenerate.returncode, 0, regenerate.stderr)
        result, report = self.gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report["failed_check"], "retained_provider_consumer")

    def test_every_generated_contract_output_is_checked_for_drift(self):
        paths = (
            "contracts/runtime-v1.schema.json",
            "contracts/openapi-v1.json",
            "src/process_runtime_client/generated.py",
            "src/process_runtime_client/runtime-v1.schema.json",
            "src/process_runtime_client/resource-templates-v1.json",
            "resources/processes/personal-review-v1.compiled.json",
            "resources/processes/development-sop-v1.compiled.json",
            "tests/fixtures/process-publication/personal-review.compiled.json",
        ) + tuple(
            f"tests/fixtures/shadow/{name}.golden.json"
            for name in (
                "personal-review-success",
                "personal-review-failure",
                "development-success",
                "development-failure",
            )
        )
        for name in paths:
            with self.subTest(path=name):
                target = self.root / name
                original = target.read_bytes()
                target.write_bytes(original + b"\n")
                try:
                    result, report = self.gate()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(
                        report["failed_check"], "deterministic_regeneration"
                    )
                    self.assertIn(name, report["detail"])
                finally:
                    target.write_bytes(original)

    def test_incompatible_actual_http_response_fails_job_command(self):
        source = self.root / "src/process_runtime/http_api.py"
        original = "            data = Snapshot.of(value).text.encode()"
        changed = (
            '            if value.get("schema") == "runtime.result.v1":\n                value = {**value, "schema": "runtime.result.v99"}\n'
            + original
        )
        self.assertIn(original, source.read_text())
        source.write_text(source.read_text().replace(original, changed, 1))
        result, report = self.gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report["failed_check"], "actual_http_provider_consumer")


if __name__ == "__main__":
    unittest.main()
