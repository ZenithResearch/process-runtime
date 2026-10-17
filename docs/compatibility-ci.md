# Runtime compatibility and candidate build gate

`runtime-api-contract-tests` requires incompatible contracts to fail before publication. The local command used by `.github/workflows/compatibility.yml` is:

```sh
python3.12 -m venv /tmp/runtime-ci-env
/tmp/runtime-ci-env/bin/python -m pip install --require-hashes -r requirements-ci.lock
/tmp/runtime-ci-env/bin/python -I scripts/ci_compatibility.py --output /tmp/runtime-compatibility-new
```

Use Python **3.12.12**, as recorded in `.python-version`. Output must be a new directory, preserving earlier evidence. The command rejects toolchain/dependency version drift. `requirements-ci.lock` pins all transitive test/build dependencies and distribution hashes, including pip and the setuptools PEP 517 backend. Tests use the interpreter's unittest. The package's consumer dependency range remains unchanged.

To build a candidate after the same checks:

```sh
/tmp/runtime-ci-env/bin/python -I scripts/ci_compatibility.py --output /tmp/runtime-candidate-new --package
```

For an offline reproduction, download the hash-verified dependencies once and pass the directory:

```sh
/tmp/runtime-ci-env/bin/python -m pip download --require-hashes --only-binary=:all: -r requirements-ci.lock -d /tmp/runtime-wheelhouse
/tmp/runtime-ci-env/bin/python -I scripts/ci_compatibility.py --output /tmp/runtime-offline-new --package --wheelhouse /tmp/runtime-wheelhouse
```

The check has three independent boundaries:

1. Both the provider validator and the public SDK validate the retained `tests/fixtures/compatibility/runtime-v1.json` baseline and current consumer fixtures. Every MVP command/query must remain represented. Keep the baseline when evolving the current schema; a deliberately versioned baseline migration requires its own consumer review. This is fixture compatibility, not a proof of arbitrary JSON Schema subsumption.
2. Two fresh interpreter processes with different hash seeds regenerate all twelve retained generated outputs and compare bytes with each other and the checkout: provider schema, SDK schema/resource templates/typed methods, OpenAPI, two process resource compilations, the publication compilation fixture, and four shadow golden results. Generators write to temporary directories; checking never updates tracked outputs.
3. The actual Runtime HTTP server and SDK run existing tests for commands/queries, authorization denial, stale versions, malformed/version-skew requests and responses, response loss, exact retry, query replay, and readiness. Isolated stores and explicit local test authority are used; no providers or production identity are involved.

Four gate regressions run the same checker CLI against disposable copies. They prove current compatibility, drift rejection for each of the twelve generated files, rejection of a new required command field **even after regeneration**, and rejection of an actual Runtime HTTP response changed to an unsupported result version. These are expected negative tests, not bypass flags in the production checker.

The full Runtime source suite runs before any candidate build, including the gate regressions. `ci/native-skips-v1.json` lists exactly 21 native test IDs and their required public fixture variables. Only those exact IDs/reasons may skip when their declared helper or fixtures are absent; missing tests, unexpected skips, and skips despite configured fixtures fail the gate. The report includes the exact count, skip IDs, source import origins, and hashes for every supplied native helper/fixture. Existing test code and native pins remain unchanged. Source tests use a no-dependency, no-build-isolation editable install under the locked toolchain so their CLI subprocesses test the same source.

The package stage runs only after the full suite and compatibility checks, builds twice from clean copies using the locked backend and `SOURCE_DATE_EPOCH=315532800`, and requires equal wheel bytes. It then installs the wheel into a fresh environment with the same hash-locked dependencies. The installed provider/SDK contract tests enforce import origins under that environment, inspect wheel bytes against checked source, and exercise the installed CLI. Files required for AST/generated-output comparisons are extracted from the wheel as reference data and kept off the import path. Native helpers, test generators, tests, and CI scripts must not appear in the wheel.

Each run retains its report, logs, wheel file/member hashes, and installed import origins. The build timestamp is a reproducibility value, not a release timestamp. Reproducibility here means identical wheel bytes from two clean builds under the declared Python/dependency toolchain; it is not a claim that the hosted runner OS image is immutable.

## Hosted execution and publication boundary

The Actions source uses pinned checkout, setup-python, and upload-artifact commits and Python 3.12.12. `candidate-wheel` requires a successful `compatibility` job and repeats the gate before building. Candidate artifact upload runs only after installed verification. The workflow has read-only repository permissions and no package-registry publisher or credentials.

At implementation time this repository has no configured remote or accessible GitHub destination. The workflow has **not** run on GitHub. Hosting it, enabling the compatibility check as a required branch/release check, and choosing/configuring a package-registry publication destination remain operator work after the repository destination is supplied. A registry publisher must depend on the successful candidate job and publish its exact verified wheel; it must not rebuild or bypass this gate. CI artifact publication is not a package-registry release.

This workflow's contract gate does not build or qualify the native secS helper, provision identities, or enable production readiness. Native-enabled local full-suite verification can supply the retained helper/public fixtures and must name their hashes with zero native skips; hosted native qualification remains separate. Existing native pins, contracts and readiness behavior are unchanged.

## Lock maintenance

The lock was generated with uv 0.11.6 using:

```sh
uv pip compile --generate-hashes --python-version 3.12.12 --universal requirements-ci.in --output-file requirements-ci.lock
```

The generator is not needed to consume the lock or run CI. Updating the input, lock, Python version, or action pin requires rerunning the complete gate and package stage. Public action pin references: [checkout v4.2.2](https://github.com/actions/checkout/commit/11bd71901bbe5b1630ceea73d27597364c9af683), [setup-python v5.6.0](https://github.com/actions/setup-python/commit/a26af69be951a213d495a4c3e4e4022e16d87065), [upload-artifact v4.6.2](https://github.com/actions/upload-artifact/commit/ea165f8d65b6e75b540449e92b4886f43607fa02).
