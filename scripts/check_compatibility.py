"""The prepublication provider/consumer gate; exits nonzero on incompatibility."""

from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

GENERATED = (
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


def emit(root, target):
    from process_runtime.contracts import write_schema
    from process_runtime.compiler import compile_draft

    for name in GENERATED:
        (target / name).parent.mkdir(parents=True, exist_ok=True)
    write_schema(target / GENERATED[0])
    spec = importlib.util.spec_from_file_location(
        "export_client", root / "scripts/export_client.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT, module.TARGET = target, target / "src/process_runtime_client"
    module.generate()
    for name in ("personal-review-v1", "development-sop-v1"):
        compiled = compile_draft(
            json.loads((root / f"resources/processes/{name}.json").read_text())
        )
        (target / f"resources/processes/{name}.compiled.json").write_text(
            json.dumps(compiled.snapshot.value, indent=2, sort_keys=True) + "\n"
        )
    fixture = "tests/fixtures/process-publication/personal-review"
    compiled = compile_draft(json.loads((root / (fixture + ".draft.json")).read_text()))
    (target / (fixture + ".compiled.json")).write_text(
        json.dumps(
            {
                "compilation_hash": compiled.compilation_hash,
                "snapshot": compiled.snapshot.value,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    from process_runtime.shadow import run_shadow

    for name in (
        "personal-review-success",
        "personal-review-failure",
        "development-success",
        "development-failure",
    ):
        process = (
            "personal-review-v1"
            if name.startswith("personal")
            else "development-sop-v1"
        )
        report = run_shadow(
            json.loads((root / f"resources/processes/{process}.json").read_text()),
            json.loads((root / f"tests/fixtures/shadow/{name}.json").read_text()),
        )
        (target / f"tests/fixtures/shadow/{name}.golden.json").write_text(
            json.dumps(report.value, indent=2, sort_keys=True) + "\n"
        )


def fixtures(root):
    from process_runtime.contracts import COMMANDS, QUERIES, validate
    from process_runtime_client.client import validate_wire

    total = 0
    for path in (
        "tests/fixtures/compatibility/runtime-v1.json",
        "contracts/consumer-fixtures-v1.json",
    ):
        data = json.loads((root / path).read_text())
        assert {item["operation"] for item in data["commands"]} == set(COMMANDS), (
            "MVP command coverage changed"
        )
        assert {item["operation"] for item in data["queries"]} == set(QUERIES), (
            "MVP query coverage changed"
        )
        for kind in ("command", "query", "event", "result", "error", "receipt"):
            values = (
                data[{"command": "commands", "query": "queries"}[kind]]
                if kind in ("command", "query")
                else [data[kind]]
            )
            for value in values:
                validate(value, kind)
                validate_wire(value, kind)
                total += 1
    return total


def regenerated(root):
    report = {}
    with tempfile.TemporaryDirectory(prefix="runtime-regenerate-") as folder:
        outputs = [Path(folder) / "first", Path(folder) / "second"]
        for seed, output in zip(("17", "7919"), outputs):
            env = {
                key: value
                for key, value in os.environ.items()
                if key not in ("PYTHONPATH", "PYTHONHOME")
            }
            env["PYTHONHASHSEED"] = seed
            # -E would erase the deliberately varied hash seed. No PYTHONPATH is inherited.
            subprocess.run(
                [
                    sys.executable,
                    "-s",
                    str(Path(__file__).resolve()),
                    "--root",
                    str(root),
                    "--emit-generated",
                    str(output),
                ],
                env=env,
                check=True,
                capture_output=True,
            )
        for name in GENERATED:
            data = (outputs[0] / name).read_bytes()
            if (
                data != (outputs[1] / name).read_bytes()
                or data != (root / name).read_bytes()
            ):
                raise ValueError("Generated output differs: " + name)
            report[name] = hashlib.sha256(data).hexdigest()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--emit-generated",
        type=Path,
        help="Regenerate only into a disposable directory; never used to approve a release",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    sys.path.insert(0, str(root / "src"))
    if args.emit_generated:
        emit(root, args.emit_generated.resolve())
        return 0
    report = {"status": "incompatible"}
    stage = "retained_provider_consumer"
    try:
        report["fixtures_validated"] = fixtures(root)
        stage = "deterministic_regeneration"
        report["generated"] = regenerated(root)
        stage = "actual_http_provider_consumer"
        suite = unittest.defaultTestLoader.discover(
            str(root / "tests"), pattern="test_http_client.py"
        )
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
        report["http_tests"] = result.testsRun
        if not result.wasSuccessful() or result.skipped or not result.testsRun:
            raise ValueError("Actual Runtime HTTP/SDK contract suite failed or skipped")
        report["status"] = "compatible"
    except Exception as exc:
        report.update(failed_check=stage, detail=str(exc))
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "compatible" else 1


if __name__ == "__main__":
    raise SystemExit(main())
