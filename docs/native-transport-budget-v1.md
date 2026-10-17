# Runtime native request transport budgets

This candidate amendment implements the reviewed service holder transport budget
without changing public schema shapes, canonical request bytes, secS Packet v0,
schema-4 context bindings, exclusive deadlines, TTL equality or production default
deny. It does not provision an identity, qualify a helper or implement service
holder issuance. New helper and wheel hashes are unqualified candidates.

## Independent byte limits

| Boundary | Bytes | Derivation / owner |
| --- | ---: | --- |
| Canonical command/query request | 2,097,152 | `contracts.MAX_REQUEST_BYTES` |
| Other public envelope shapes | 1,048,576 | `contracts.MAX_ENVELOPE_BYTES`, unchanged |
| Native proof | 16,384 | Reviewed bounded profile; independently checked after Packet decoding |
| Packet v0 fixed layout | 69 | Fixed-integer bincode fields excluding proof/request contents |
| Whole native Packet | 2,113,605 | Request + proof + fixed layout |
| Signed native context | 65,536 | Unchanged independent decoder bound |
| Native authority JSON | 4,400,000 | Existing receiver cap, unchanged |
| Maximum native envelope for bounded Packet/context | 4,358,359 | 2 × Packet + 2 × context + 77 JSON framing bytes |
| Base64 authority | 5,866,668 | 4 × ceil(4,400,000 / 3) |
| HTTP transport body | 18,449,646 | 6 × request + base64 authority + 66 wrapper bytes |
| Helper typed metadata / JSON framing | 65,536 | Excludes the three hex contents; includes escaped labels/keys |
| Maximum derived helper stdin | 8,618,122 | 2 × Packet + 2 × request + 2 × context + metadata |
| Helper stdin hard limit | 9,437,184 | Existing 9 MiB limit, unchanged |
| Helper stdout | 131,072 | Existing Python limit; now also enforced before native stdout write |
| Public SDK response | 4,500,000 | Unchanged |

The old Python `contracts.validate` implementation applied 1 MiB to **every**
envelope. This was a consumer inconsistency with the reviewed 2 MiB native request
profile; the previous release did not accept all 2 MiB commands. This amendment
changes only command/query envelope admission. Compiler documents, typed values,
results, events, receipts, artifacts and query results retain their independent
limits. A 2 MiB envelope is not a promise that its operation-specific inputs or
result fit. In particular, full 2 MiB run/handoff inputs remain invalid under the
unchanged 1 MiB typed-value limit. A handoff with exactly 1 MiB of canonical inputs
plus its command framing can now enter, commit and retry with a small result.

The unchanged public SDK uses `ensure_ascii=True`. Accepted opaque DEL (U+007F)
expands from one canonical UTF-8 byte into six ASCII escape bytes. Sixfold is the
conservative request bound; assuming only threefold Unicode expansion is wrong.
The existing 4.4 MB authority limit remains independent: the HTTP handler checks
encoded length before base64 decoding and decoded length afterward. Duplicate
keys, nonfinite JSON, malformed UTF-8, unknown envelope fields, bad base64 and
over-limit framing remain errors. Existing URL and response policies are unchanged.

## Bounded local admission

Each HTTP server permits two in-flight request bodies, including parsing, handler
execution and response serialization. A third framed request gets the existing
retryable `storage_unavailable` / HTTP 503 response before reading its body. Every
success and error releases the admission, including malformed JSON, incomplete
body, timeout and handler failure. This bounds concurrently admitted body bytes
to 36,899,292; decoding/canonicalization adds bounded copies and Python object
overhead, so that number is not a process RSS guarantee. Header/thread and overall
deployment resource qualification remain separate from this source amendment.

The existing five-second body read allowance is now an absolute deadline, sampled
before reading. Reads use at most 65,536-byte chunks and the remaining deadline as
their socket timeout, so partial progress cannot reset the allowance. The final
completed read also samples the clock and rejects at or after the deadline before
parsing or resetting the response timeout. A completed body restores the ordinary five-second socket timeout before response work. Framing
errors remain HTTP 400; socket/deadline failures retain HTTP 503 semantics. No
handler or native authority limit is relaxed to accommodate a large body.

## Verification and candidate artifacts

`tests/test_transport_budget.py` separates nine inert maximum authority framing
cases from actual native signature fixtures. It feeds the real public SDK and
real HTTP request handler through an in-memory socket adapter, and independently
tests slow progress with a real isolated loopback socket. Maximum cases cover
ASCII, DEL, BMP, supplementary Unicode, quotes, backslashes, LF, NUL and mixed
escapes. Exact cap and cap+1, malformed envelopes, independent native proof/context
limits, default deny and capacity release are covered. The actual Runtime handoff
test uses a temporary private store: maximum admitted typed inputs commit once,
exact retry returns the original result, and operation-level over-limit input
denies without mutation. No live database/provider is involved.

The native `cfg(test)` fixture generator uses the existing historical synthetic
signer. The release helper contains no generator or signer. Request generation
is pure Python serialization with no signing; optional exact request files and a
hash manifest include maximum and +1 cases plus numeric/control values for paired
native reader checks. These fixtures are compatibility evidence, not issuer or
service custody qualification.

Always build this amendment to a **new** target directory. Do not overwrite the
previously reviewed helper or an immutable retained wheel:

```sh
cargo +1.96.0 test --locked --offline --release --manifest-path native/secs-verifier/Cargo.toml --target-dir /example/tmp/runtime-budget-candidate
cargo +1.96.0 build --locked --offline --release --manifest-path native/secs-verifier/Cargo.toml --target-dir /example/tmp/runtime-budget-candidate
.venv/bin/python tests/generate_transport_fixture_input.py /example/tmp/runtime-budget-input.json /example/tmp/runtime-budget-request-vectors
RUNTIME_SECS_FIXTURE_INPUT=/example/tmp/runtime-budget-input.json RUNTIME_SECS_FIXTURE_OUTPUT=/example/tmp/runtime-budget-fixtures.json cargo +1.96.0 test --locked --offline --release --manifest-path native/secs-verifier/Cargo.toml --target-dir /example/tmp/runtime-budget-candidate retained_synthetic_fixtures
PROCESS_RUNTIME_NATIVE_VERIFIER=/example/tmp/runtime-budget-candidate/release/process-runtime-secs-verifier PROCESS_RUNTIME_TRANSPORT_FIXTURES=/example/tmp/runtime-budget-fixtures.json .venv/bin/python -m unittest discover -s tests -v
```

Installed verification must use a fresh wheel environment with no component
source overrides, the exact candidate helper hash and copied public fixtures.
Older small public requests and retained native fixtures remain accepted. Proofs
exceeding the reviewed 16 KiB profile bound now reject even if a smaller request
leaves Packet capacity. Public request shape and canonical bytes are unchanged;
deploying either candidate artifact still requires independent review and the
separate installed authority qualification gates.
