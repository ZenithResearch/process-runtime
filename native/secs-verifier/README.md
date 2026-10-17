# Native secS verification-only helper

This stdin/stdout receiver adapter verifies the actual secS schema-4 signed bincode context and exact packet bytes. It has no key creation, credential issuing, signing command, private-key read, grant administration, network client, installation or replay-store interface. `Cargo.lock` pins the complete dependency resolution. The secS source dependency is pinned to `11e7128e49c6df57f53e4c8b05e72d4bc78d798c` in `Cargo.toml`.

From the repository root, with Rust 1.96.0 and dependencies already cached:

```sh
cargo +1.96.0 build --locked --offline --release --manifest-path native/secs-verifier/Cargo.toml --target-dir /example/tmp/process-runtime-secs-verifier-target
cargo +1.96.0 test --locked --offline --release --manifest-path native/secs-verifier/Cargo.toml --target-dir /example/tmp/process-runtime-secs-verifier-target
PROCESS_RUNTIME_NATIVE_VERIFIER=/example/tmp/process-runtime-secs-verifier-target/release/process-runtime-secs-verifier .venv/bin/python -m unittest discover -s tests -p test_authority.py -v
```

Without the environment variable, the five Python native integration tests explicitly skip. The other ten authority binding/policy tests still run. To regenerate the public synthetic fixtures using the native Rust types and signature API, choose an output outside the retained fixture first and compare:

```sh
RUNTIME_SECS_FIXTURE_INPUT="$PWD/tests/fixtures/authority/native-fixture-input.json" RUNTIME_SECS_FIXTURE_OUTPUT=/example/tmp/native-secs-v4-regenerated.json cargo +1.96.0 test --locked --offline --release --manifest-path native/secs-verifier/Cargo.toml --target-dir /example/tmp/process-runtime-secs-verifier-target retained_synthetic_fixtures
cmp tests/fixtures/authority/native-secs-v4.json /example/tmp/native-secs-v4-regenerated.json
```

The fixture generator and fixed synthetic signer seed are compiled only for tests. The release executable accepts no arguments, reads a closed `process-runtime.secs-check-input.v1` object from stdin, and returns a closed `process-runtime.secs-check-output.v1` object. Requests carry only public receiver configuration, public signed context/packet bytes and canonical runtime request bytes. Any rejection emits the fixed error `native_authority_rejected` and exits 2 without echoing inputs.

This is isolated source validation, not live security-stack qualification. The runtime's production default remains deny. Deployment needs an independently approved binary hash and receiver-owned policy; test success does not authorize a historical native signer, generic stack migration or machine-identity provisioning. See `../../docs/receiver-authority-v1.md` for the exact trust and transactional boundaries.

## Public build closure

The pinned upstream secS revision names a retired private Wallet dependency. This
helper patches only that dependency source to the public Wallet compatibility
crate at `c6e3007216e90a99ffb7b7cb1b34a9f7c29e1a1f`. The compatibility crate lives
in Wallet’s own repository and records exact source provenance. No Wallet source
is copied into Runtime. The Rust verifier implementation, protocol bindings,
receiver policy and authority behavior are unchanged. Actual locked Cargo metadata
was verified with no private Wallet cache or credentials. Public CI builds this
helper and exercises actual Native signatures and rejection paths in Frank.
This establishes source portability, not production authority qualification.
