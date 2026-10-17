# Versioned process resources and shadow comparisons

`resources/processes/personal-review-v1.json` encodes the nine-handler review procedure retained from Hub. Its neighboring Markdown contains the same explicit `process-json` block; only that block defines executable structure. The compiled snapshot is retained and checked byte-semantically by tests. The original profile and complete procedure Markdown are retained under `resources/sources`, with their byte hashes and classified migration changes in `personal-review-v1.migration.json`.

The resource preserves load, transcription, component resolution, annotation, extraction, source binding, review writing, status writeback and daily-note ordering. The legacy profile listed transcription and component resolution as roots even though the written procedure consumes load-step outputs. Both now explicitly depend on `step_1`; transcription and component resolution can then execute concurrently. Every output binding references a declared ancestor.

Step 7 explicitly emits the final source-bound packet and quality status for step 8: the legacy writer overwrites the step 5 path, while published artifacts are immutable. Mutable audio/note/packet path ports become content-addressed artifact references; a migration map identifies each renamed port. Closed normalized event, word, component, observation and context schemas make type mismatches explicit. The richer original evidence remains in artifacts; undeclared fields require a reviewed process version rather than being silently accepted. Native review/STT/vault/status integrations are not implemented by this resource or the shadow harness.

The procedure's semantic obligations still belong to real handlers: preserve reviewer speech, keep silent gestures as negative evidence, explicitly mark unresolved component/source evidence, validate packet quality before status writeback, and record delivery effects through the fenced runtime protocol. A successful typed output alone does not prove those integrations have run. The development fixture follows the same rule: a failed test or rejected review must fail its Attempt; a boolean output by itself is data and does not alter DAG readiness.

`resources/processes/development-sop-v1.json` is independent of Service Request and Case. It scopes a change, implements it, runs unit and consumer-contract branches, joins their evidence for review, and packages the result. It uses the same draft/compiler/public command, query, claim, completion and receipt contracts as personal review. Neither the runtime scheduler nor the shadow runner branches on process names or handler identities.

## Retained pins

| Process | Compilation SHA-256 |
| --- | --- |
| personal-review-v1 | `911747b69cf2b2f58a10db76ac3d523b96acbc103d2adcaad1cb01c61572eb25` |
| development-sop-v1 | `f0fff8e5f98ab2132632b1f810af130d6a0c2b8ad29e08d4d3bab769539ce711` |

These are publication inputs and retained compiler outputs. Tests publish them through `process.draft.put` and `process.publish` into disposable SQLite stores; nothing publishes them to a live runtime or changes existing run pins. The small three-step `tests/fixtures/process-publication/personal-review.*` files remain compiler/authoring unit examples, not the full personal-review SOP.

## Shadow execution

`process_runtime.shadow.run_shadow(draft, fixture)` accepts a closed fixture containing explicit UTF-8 artifact content and one fixed success-or-failure outcome per step. It creates a private temporary runtime database, imports artifacts, publishes the process, registers a fixture Actor, creates a run, and uses the public executor commands. It claims each ready batch before completing the batch, so parallel-branch behavior is exercised. It queries outputs, Attempts and receipts through public APIs; it never reads store records to obtain execution state.

The fixture program has no callable/import/handler hook. Its command allowlist excludes all effect commands and it has no integration callback, service client, external artifact URI fetch, build subprocess or note-write operation. Artifact strings describe synthetic fixtures only. All authority is explicitly `local_dev_untrusted` in the test environment; no production credential is issued or accepted. The report records `external_effects: forbidden`.

Four scenario/golden pairs are retained in `tests/fixtures/shadow`:

| Scenario | Runnable batches | Terminal result |
| --- | --- | --- |
| Personal review success | load; transcription + resolution; annotation; extraction; source binding; review; status; daily note | succeeded |
| Personal review failure | load; transcription + resolution | failed; resolution completion retained, annotation waits |
| Development success | scope; implement; contract + unit; review; package | succeeded |
| Development failure | scope; implement; contract + unit | failed; unit completion retained, review waits |

Reports retain compilation hash, runnable batches, input/output digests, normalized receipts and their hashes, classified failure reasons, and terminal states. Random Attempt and receipt IDs are replaced with deterministic step-and-ordinal aliases solely in the report; actual runtime receipts remain immutable and retain their allocated IDs. All other receipt fields, including pin, fence, Actor, input/output digests, timestamps and outcome, remain part of the golden hash. The clock is a fixed fixture value. This is a semantic receipt comparison, not a claim that runtime-generated receipt bytes or identifiers are deterministic.

`compare_shadow` retains every field-level divergence and classifies it as runnable, input, output, receipt, failure, terminal state, compilation, execution or report contract. It never rewrites expected fixtures. Reviewed source migration differences are separate from runtime divergences; zero golden divergences does not claim equivalence with an executed legacy production pipeline.

Run:

```sh
.venv/bin/python -m unittest discover -s tests -p test_shadow.py -v
```

The suite compares all four goldens, reruns a fresh database to check normalized receipt stability, validates the retained source hashes and Markdown/compiler parity, exercises parallel failure, and rejects fixture effect/callable extensions and wrong output types. Updating a golden requires an explicit reviewed fixture/source change and a retained explanation of the difference.
