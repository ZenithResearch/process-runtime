import json
from pathlib import Path
import unittest

from process_runtime.authoring import import_document
from process_runtime.compiler import compile_draft

ROOT = Path(__file__).resolve().parents[1]
NAME = "zenith.anima.brand-package"
HASH = "1b4848c714775871a7b1cee4b04d73e43994e30838ec5a312ea10993d0b07ee2"


class BrandPackageProcessTests(unittest.TestCase):
    def load(self, suffix: str):
        return json.loads((ROOT / "resources" / "processes" / f"{NAME}.{suffix}").read_text())

    def test_reviewed_markdown_json_and_compiled_snapshot_are_identical(self):
        draft = self.load("json")
        source = import_document(
            (ROOT / "resources" / "processes" / f"{NAME}.md").read_bytes(),
            source_id=NAME,
            media_type="text/markdown",
        )
        self.assertTrue(source.accepted, source.uncertainties)
        self.assertEqual(source.draft.value, draft)
        compiled = compile_draft(source.draft)
        self.assertEqual(compiled.compilation_hash, HASH)
        self.assertEqual(compiled.snapshot.value, self.load("compiled.json"))

    def test_contract_matches_first_anima_service_and_keeps_review_explicit(self):
        draft = self.load("json")
        self.assertEqual(
            set(draft["inputs"]),
            {"organization_name", "reviewed_brief", "reference_manifest"},
        )
        steps = {step["step_id"]: step for step in draft["steps"]}
        self.assertEqual(
            set(steps["research-market"]["depends_on"]), {"qualify-intake"}
        )
        self.assertEqual(
            set(steps["research-visual"]["depends_on"]), {"qualify-intake"}
        )
        self.assertEqual(steps["human-approval"]["max_attempts"], 1)
        self.assertEqual(
            steps["human-approval"]["capabilities"], ["brand.review.human"]
        )
        self.assertEqual(
            steps["package-deliverables"]["bindings"]["approved"],
            {"source": "step_output", "step_id": "human-approval", "name": "approved"},
        )
        self.assertEqual(
            set(steps["package-deliverables"]["outputs"]),
            {"brand_package", "deliverable_manifest", "quality_report"},
        )
        self.assertTrue(
            all(spec == {"kind": "artifact"} for spec in steps["package-deliverables"]["outputs"].values())
        )


if __name__ == "__main__":
    unittest.main()
