"""Unexpected skipped business or configured native tests must block publication."""

from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "runtime_ci_suite", ROOT / "scripts/run_runtime_suite.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SkipPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policies = [
            {
                "id": "native.signature",
                "reason": "fixture missing",
                "requires": ["NATIVE_FIXTURE"],
            }
        ]

    def test_only_exact_unavailable_native_skip_is_allowed(self):
        self.assertEqual(
            MODULE.evaluate_skips(
                [("native.signature", "fixture missing")], self.policies, {}
            ),
            {"native.signature": "fixture missing"},
        )

    def test_business_test_skip_cannot_hide_in_native_allowlist(self):
        with self.assertRaises(ValueError):
            MODULE.evaluate_skips(
                [
                    ("native.signature", "fixture missing"),
                    ("runtime.commit", "disabled"),
                ],
                self.policies,
                {},
            )

    def test_configured_native_test_must_run(self):
        with self.assertRaises(ValueError):
            MODULE.evaluate_skips(
                [("native.signature", "fixture missing")],
                self.policies,
                {"NATIVE_FIXTURE": "/fixture"},
            )
        self.assertEqual(
            MODULE.evaluate_skips([], self.policies, {"NATIVE_FIXTURE": "/fixture"}), {}
        )


if __name__ == "__main__":
    unittest.main()
