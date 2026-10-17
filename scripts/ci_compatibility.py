"""Run the compatibility gate; optionally build and verify a candidate wheel."""

from pathlib import Path
import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    raw = path.read_bytes()
    return {
        "path": str(path),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def environment():
    return {
        key: value
        for key, value in os.environ.items()
        if key not in ("PYTHONPATH", "PYTHONHOME")
    }


def locked_toolchain():
    wanted = (ROOT / ".python-version").read_text().strip()
    actual = ".".join(map(str, sys.version_info[:3]))
    if actual != wanted:
        raise ValueError(f"Expected Python {wanted}; got {actual}")
    versions = {}
    for name, version in re.findall(
        r"^([a-zA-Z0-9_-]+)==([^ ;\\\n]+)",
        (ROOT / "requirements-ci.lock").read_text(),
        re.M,
    ):
        actual = importlib.metadata.version(name)
        if actual != version:
            raise ValueError(
                f"Install requirements-ci.lock: {name} expected {version}, got {actual}"
            )
        versions[name] = version
    return {
        "python": wanted,
        "dependencies": versions,
        "lock": digest(ROOT / "requirements-ci.lock"),
    }


def run(argv, log, *, cwd=ROOT, env=None):
    with log.open("w") as output:
        subprocess.run(
            argv,
            cwd=cwd,
            env=env or environment(),
            stdout=output,
            stderr=subprocess.STDOUT,
            check=True,
        )


def installed_check(wheel, output, wheelhouse):
    destination = output / "installed"
    run([sys.executable, "-I", "-m", "venv", str(destination)], output / "venv.log")
    python = destination / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    pip = [str(python), "-I", "-m", "pip", "--disable-pip-version-check", "install"]
    location = ["--no-index", "--find-links", str(wheelhouse)] if wheelhouse else []
    run(
        pip + location + ["--require-hashes", "-r", str(ROOT / "requirements-ci.lock")],
        output / "install-dependencies.log",
    )
    run(pip + ["--no-index", "--no-deps", str(wheel)], output / "install-wheel.log")
    stage = output / "installed-tests"
    for name in ("tests", "contracts", "resources", "scripts"):
        shutil.copytree(
            ROOT / name,
            stage / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    members = []
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.endswith("/"):
                continue
            if name.startswith(("native/", "tests/", "scripts/", ".github/")):
                raise ValueError("Non-package source included in wheel: " + name)
            data = archive.read(name)
            members.append(
                {
                    "path": name,
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
            if name.startswith(("process_runtime/", "process_runtime_client/")):
                if data != (ROOT / "src" / name).read_bytes():
                    raise ValueError("Wheel differs from checked source: " + name)
                reference = stage / "src" / name
                reference.parent.mkdir(parents=True, exist_ok=True)
                reference.write_bytes(data)
    (output / "wheel-members.json").write_text(json.dumps(members, indent=2) + "\n")
    runner = output / "verify-installed.py"
    runner.write_text("""from pathlib import Path
import importlib.abc,importlib.machinery,json,sys,unittest
stage=Path(sys.argv[1]);prefix=Path(sys.prefix).resolve()
def component(name):return name=='process_runtime' or name.startswith('process_runtime.') or name=='process_runtime_client' or name.startswith('process_runtime_client.')
class Guard(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if component(fullname):
   spec=importlib.machinery.PathFinder.find_spec(fullname,path,target)
   assert spec and spec.origin and Path(spec.origin).resolve().is_relative_to(prefix),(fullname,spec)
   return spec
sys.meta_path.insert(0,Guard())
suite=unittest.TestSuite()
for pattern in ('test_contracts.py','test_public_client_contract.py','test_http_client.py'):
 suite.addTests(unittest.defaultTestLoader.discover(str(stage/'tests'),pattern=pattern))
result=unittest.TextTestRunner(verbosity=2).run(suite)
origins={name:str(Path(module.__file__).resolve()) for name,module in sys.modules.items() if component(name) and getattr(module,'__file__',None)}
assert origins and all(Path(path).is_relative_to(prefix) for path in origins.values())
assert str(stage/'src') not in sys.path
Path(sys.argv[2]).write_text(json.dumps({'tests':result.testsRun,'skips':result.skipped,'success':result.wasSuccessful(),'prefix':str(prefix),'origins':origins},indent=2)+'\\n')
raise SystemExit(0 if result.wasSuccessful() and not result.skipped and result.testsRun else 1)
""")
    run(
        [
            str(python),
            "-I",
            str(runner),
            str(stage),
            str(output / "installed-origins.json"),
        ],
        output / "installed-contract-tests.log",
        cwd=stage,
    )
    run(
        [str(python), "-I", "-m", "process_runtime", "--help"],
        output / "installed-cli-help.log",
        cwd=stage,
    )
    return json.loads((output / "installed-origins.json").read_text())


def build(output, wheelhouse):
    results = []
    # Two clean directories and a fixed ZIP timestamp prove byte reproducibility locally.
    for label in ("build-a", "build-b"):
        source = output / label
        source.mkdir()
        for name in ("pyproject.toml", "README.md"):
            shutil.copyfile(ROOT / name, source / name)
        for name in ("src", "resources"):
            shutil.copytree(
                ROOT / name,
                source / name,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"),
            )
        env = {**environment(), "SOURCE_DATE_EPOCH": "315532800", "PYTHONHASHSEED": "0"}
        run(
            [
                sys.executable,
                "-I",
                "-c",
                "from setuptools.build_meta import build_wheel; build_wheel('wheel')",
            ],
            output / (label + ".log"),
            cwd=source,
            env=env,
        )
        wheels = list((source / "wheel").glob("*.whl"))
        if len(wheels) != 1:
            raise ValueError("Expected exactly one built wheel")
        results.append(wheels[0])
    if results[0].read_bytes() != results[1].read_bytes():
        raise ValueError("Clean builds produced different wheel bytes")
    wheel = output / "dist" / results[0].name
    wheel.parent.mkdir()
    shutil.copyfile(results[0], wheel)
    installed = installed_check(wheel, output, wheelhouse)
    return {
        "wheel": digest(wheel),
        "reproducible": True,
        "source_date_epoch": 315532800,
        "installed": installed,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True, help="New empty evidence directory"
    )
    parser.add_argument(
        "--package",
        action="store_true",
        help="Build only after the compatibility and negative checks succeed",
    )
    parser.add_argument(
        "--wheelhouse",
        type=Path,
        help="Optional local distribution directory; disables install network access",
    )
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "status": "failed",
        "execution_context": "github-actions"
        if os.environ.get("GITHUB_ACTIONS") == "true"
        else "local",
        "production_qualified": False,
    }
    try:
        report["toolchain"] = locked_toolchain()
        run(
            [sys.executable, "-I", str(ROOT / "scripts/check_compatibility.py")],
            output / "compatibility.log",
        )
        report["compatibility"] = json.loads(
            (output / "compatibility.log").read_text().splitlines()[-1]
        )
        run(
            [
                sys.executable,
                "-I",
                "-m",
                "pip",
                "--disable-pip-version-check",
                "install",
                "--no-deps",
                "--no-build-isolation",
                "--editable",
                str(ROOT),
            ],
            output / "install-source.log",
        )
        source_env = environment()
        source_env.pop("PROCESS_RUNTIME_CRASH_INSTALLED", None)
        run(
            [
                sys.executable,
                "-I",
                str(ROOT / "scripts/run_runtime_suite.py"),
                "--report",
                str(output / "source-suite.json"),
            ],
            output / "source-suite.log",
            env=source_env,
        )
        report["source_suite"] = json.loads((output / "source-suite.json").read_text())
        if args.package:
            report["package"] = build(
                output, args.wheelhouse.resolve() if args.wheelhouse else None
            )
        report["status"] = "passed"
    except Exception as exc:
        report["error"] = str(exc)
    finally:
        report["logs"] = [digest(path) for path in sorted(output.glob("*.log"))]
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps({"status": report["status"], "report": str(output / "report.json")})
    )
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
