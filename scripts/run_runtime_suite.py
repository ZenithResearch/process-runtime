"""Run every Runtime test; only explicitly unavailable native fixtures may skip."""

from pathlib import Path
import argparse
import hashlib
import importlib.abc
import importlib.machinery
import json
import os
import sys
import unittest


def evaluate_skips(skips, policies, environment):
    expected = {
        item["id"]: item["reason"]
        for item in policies
        if not all(environment.get(name) for name in item["requires"])
    }
    actual = dict(skips)
    if actual != expected:
        raise ValueError(
            "Unexpected or missing skips: "
            + json.dumps({"expected": expected, "actual": actual}, sort_keys=True)
        )
    return expected


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    source = root / "src"
    sys.path.insert(0, str(source))

    def component(name):
        return any(
            name == prefix or name.startswith(prefix + ".")
            for prefix in ("process_runtime", "process_runtime_client")
        )

    class SourceGuard(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if component(fullname):
                spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
                assert (
                    spec
                    and spec.origin
                    and Path(spec.origin).resolve().is_relative_to(source)
                ), fullname
                return spec

    sys.meta_path.insert(0, SourceGuard())
    policies = json.loads((root / "ci/native-skips-v1.json").read_text())["tests"]
    tests = list(flatten(unittest.defaultTestLoader.discover(str(root / "tests"))))
    ids = {test.id() for test in tests}
    if len(tests) < 148 or not {item["id"] for item in policies} <= ids:
        raise ValueError("Full Runtime/native inventory was not discovered")
    # Preserve fresh native fixture windows; the slow disposable-copy CI regressions run last.
    tests.sort(key=lambda test: test.id().startswith("test_compatibility_gate."))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(tests))
    skips = [(test.id(), reason) for test, reason in result.skipped]
    rejection = None
    try:
        evaluate_skips(skips, policies, os.environ)
    except ValueError as exc:
        rejection = str(exc)
    origins = {
        name: str(Path(module.__file__).resolve())
        for name, module in sys.modules.items()
        if component(name) and getattr(module, "__file__", None)
    }
    if not all(Path(path).is_relative_to(source) for path in origins.values()):
        rejection = "Runtime source import origin changed"
    native = {}
    for name in (
        "PROCESS_RUNTIME_NATIVE_VERIFIER",
        "PROCESS_RUNTIME_TRANSPORT_FIXTURES",
        "PROCESS_RUNTIME_FRESH_NATIVE_FIXTURES",
    ):
        if os.environ.get(name):
            path = Path(os.environ[name])
            raw = path.read_bytes()
            native[name] = {
                "path": str(path),
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
    report = {
        "tests": result.testsRun,
        "passed": result.testsRun
        - len(result.skipped)
        - len(result.errors)
        - len(result.failures),
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skips": skips,
        "skip_policy_rejection": rejection,
        "success": result.wasSuccessful() and rejection is None,
        "origins": origins,
        "native_fixture_evidence": native,
        "production_qualified": False,
    }
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
