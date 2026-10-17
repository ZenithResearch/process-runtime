# Runtime API and executor contract v1

The standalone `contracts/runtime-v1.schema.json` is the closed wire contract. `contracts/openapi-v1.json` describes HTTP transport. `scripts/export_client.py` generates Python TypedDict payloads, typed operation methods, packaged schema and resource metadata in the public `process_runtime_client` package. Service management and Frank import that package, never runtime storage or domain implementation modules.

The HTTP adapter exposes `/live`, `/ready`, `POST /v1/commands` and `POST /v1/queries`. Both POST routes accept `{schema: "runtime.transport.v1", request: <wire envelope>, authority_base64: <native evidence bytes>}`. They reject duplicate JSON fields, unsupported contracts, unknown properties, malformed framing and oversized bodies. Production defaults to deny-all authority. The local development option is explicit, visible in events/results, and rejected in production. Readiness requires healthy storage and an explicitly enabled local development authority; default-deny and unqualified production adapters report 503. A liveness response is not production authority qualification.

Commands contain schema, operation, request_id, resource, expected_version and payload. Queries contain schema, operation and payload. Use public `command_envelope(...)` or `resource_for(envelope)` for canonical resource derivation. Resource spelling is plural (`processes/id`, `runs/id`, `actors/id`). Executor calls bind `runs/{run_id}/steps/{step_id}` plus exact Attempt/fence fields in the payload. Handoff scope is `handoffs/` plus SHA-256 of canonical JSON `{source,event_id}`. The full generated mapping is `resource-templates-v1.json`.

The receiver checks its pinned native secS verification key, signed context, exact bincode packet and payload, active manifest descriptor, operation/opcode, audience, subject/key revocation, validity and receiver permission rules. Deny rules win. Replay admission, current Actor ownership, expected versions and lease fences are checked transactionally. An Actor directory reference is not an authentication identity. Matrix, Hermes, caller keys, source addresses and display names never grant authority.

## Commands and versions

Draft creation uses a null version; updates use the current draft record version. Publishing requires that record version plus the exact draft revision. It stores source/provenance, compiled snapshot and immutable pin. Publishing advances the draft record's publication ordinal and active_version pointer without modifying existing versions or runs.

Run creation, Actor registration, content-addressed artifact insertion and handoff consumption use null expected versions. Every executor mutation uses the current **step version**. Claim returns step_version, run_version, pin, Attempt, fence, typed inputs/output types and lease expiry. Heartbeat and effect calls each advance step_version. Run cancel/retry use the run version; effect.resolve uses the effect version. A stale version is rejected, never automatically rebased by the client.

`run.retry` applies only to a blocked retryable step within its attempt budget. It does not revive terminal runs. Releasing safe work or recovering an expired safe lease makes the step ready; its next claim always creates a new Attempt. Completing typed outputs, immutable output/receipt insertion, step completion and downstream readiness share a transaction.

Effects have a deterministic Attempt/effect-name identity. Record intent, then dispatch before sending to the provider, then observation. Acknowledged is not succeeded. A second dispatch is rejected; ambiguous delivery is reconciled rather than automatically repeated. An idempotent retry of a committed command returns `duplicate: true`; it is not fresh permission to issue an external effect.

## Queries and events

`version.get` returns pin, ordinal, source_revision, published_at_ms, compiled snapshot, source_draft and provenance. `run.get` returns the immutable pin and inputs, canonical state/version and step summaries. `attempt.get` binds run/step/Attempt and returns Actor, ordinal, inputs/digest/types, output types, current fence, current step version and lease expiry. Attempt reads also expose deterministic trace/span identities and timestamps derived from the canonical Attempt. Executors must require a current active unexpired Attempt before resuming; every mutation still rechecks it.

`output.get` returns the exact immutable output identity, run/step/Attempt/fence, pin, Actor, inputs_digest, output values/types/digest, commit timestamp and receipt reference. `receipt.get`, `effect.get` and `artifact.get` retrieve their exact records. Work discovery filters committed dependency readiness and Actor capabilities/resources; claiming remains the atomic authority check.

`events.list` returns events, next_cursor and high_watermark. A page limit is not proof of catching up. The public SDK event_pages iterator bounds page count and validates cursor continuity, gaps and progress; future cursors are rejected. Consumers needing contiguous global gap detection poll without a run filter. Filtered reads still advance through the global cursor. Event summaries contain explicit run_state/run_version and step_state/step_version when applicable; they omit raw inputs, outputs, source documents and authority evidence. They are rebuildable observations, not another execution owner.

## Errors, retries and receipts

The client raises `RuntimeClientError` with code, retryable, uncertain and optional current_version. Transport loss or an incompatible/malformed success acknowledgement after a command is uncertain. Retain and resend the identical command with fresh proof; do not invent a replacement request or increment its version. Closed application rejection is distinct from transport ambiguity. There is no automatic retry or broad signing facility.

Receipts are unsigned MVP integrity envelopes. `receipt_verifier.verify_receipt` checks a receipt against trusted version, Attempt and immutable output records, including hashes, Actor, fences, types and times. It cannot authenticate a collection of mutually replaced untrusted records. The reserved signature field is null; future Castalia signatures must preserve these execution bindings and use an explicit compatible schema extension. No signing parity is claimed today.

## Native receiver entrypoint

The runtime CLI can inject its receiver-owned native adapter using `--receiver-config`
with a closed private public-policy configuration. Missing configuration retains
default deny; invalid supplied configuration rejects startup. Helper hashes and
operator file controls are checked, while public permissions and revocations reload
for each verification. See `receiver-authority-v1.md` for exact field shapes.
Readiness preserves the new-run admission status and reports configured native
verification availability separately from its still-unqualified authority chain;
matching pins cannot produce production-ready status.
