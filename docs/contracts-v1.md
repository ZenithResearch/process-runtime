# Runtime v1 contracts

Tasks: `runtime-contracts-domain-model`, `runtime-contracts-command-event-spec`.

The canonical schema bundle is generated from `src/process_runtime/contracts.py`:

```sh
.venv/bin/python scripts/export_contract.py
.venv/bin/python -m unittest discover -s tests -v
```

`contracts/runtime-v1.schema.json` is the distributable contract. Consumer fixtures
cover every declared command and query plus event, result, error and unsigned
receipt envelopes. Consumers must validate this public contract or use its client;
imports of runtime domain/storage internals are not a supported integration.
OpenAPI, the generated public client and the bounded HTTP API are implemented;
see `api-and-executor-v1.md` for their command and query semantics.

All command envelopes contain exactly `schema`, `operation`, `request_id`,
`resource`, `expected_version`, and `payload`. Unknown fields and contract versions
fail closed. Authentication travels through an adapter outside these envelopes;
a caller-provided Actor, public key, bearer or Matrix identity cannot authorize a
command. Resource/payload equality is a mandatory application check. Envelope
validation alone is not authorization, DAG validation, or execution.

Canonical command bytes are UTF-8 JSON with sorted string keys, no insignificant
whitespace and only finite JSON values. The digest binds every command field,
including request ID, expected version, exact run/step/Attempt/fence and payload.
`Snapshot` retains canonical text by value so a caller cannot change a published
snapshot or run inputs after construction. Published versions and active run pins
are immutable. Draft edits use a new optimistic revision; editing never repins an
existing run. The ProcessDefinition identity must match the retained draft's
`process_id`; an edit cannot move a draft to another Process. Run `source_ref` is
an optional opaque reference of 1–4096 characters, matching the public v1 command
bound. No ServiceRequest or Case is required for a run. Actor capability/resource
entries are stable identifiers in immutable unique tuples; malformed entries
produce domain rejection before any collection operation can fail.

Idempotency is scoped by authenticated subject and request ID. Exact retry returns
the original durable result; changed bytes under the same ID conflict. A retry
must re-establish current authority and may not bypass expiry or revocation.
Unknown transport outcomes require reconciliation with the exact retained
command. A new execution retry allocates a new Attempt ID and monotonic fence;
it is not an idempotent retry of the previous Attempt. Application commands must
explicitly audit any retry of a failed run/step. Terminal Attempt values never
transition back to active, and plain state transitions never reopen terminal runs
or steps.

Mutating existing state requires a positive expected version. Create/upsert
operations can represent initial absence with null; the application must reject
null if the object already exists except exact idempotent replay. Heartbeats and
completion require the current step version, exact Attempt and fence. Lease expiry
is exclusive: `now >= expires_at` rejects the holder. Recovered work increments
its fence, invalidating late writes. One transaction must persist output values,
references, output digest, terminal Attempt, step/run state, event and receipt
before completion becomes visible. The domain checks value invariants; the application and SQLite adapter enforce
this transaction boundary, exercised by storage, concurrent-claim and process-death
regression tests.

Commands cover draft save/publication, run creation/cancellation/explicit retry,
artifact commit, Actor registration/advertisement, claim/heartbeat/complete/fail/
release, effect intent/dispatch/observation/reconciliation and accepted-work inbox
delivery. Queries cover definitions, versions, runs, eligible work, Attempts,
outputs, effects, events, artifacts and receipts. Query pagination is bounded.
Event cursors identify canonical retained history; event-bus wakeups do not define
state. Event and result resource examples use the same canonical plural paths as
the originating command and the public SDK. The ownership inventory accounts for
every persisted runtime kind and public query source, including RuntimeEffect.
The separate Frank external-effect journal retains provider evidence and exact
command acknowledgements; runtime effect state controls completion and recovery.
A missing cursor must produce `cursor_gap`, never silent loss.

A receipt binds the ProcessVersion/hash, run, step, Attempt, Actor, input/output
digests, fence, timestamps and terminal outcome. Successful receipts require an
output digest. The MVP wire `signature` field is explicitly null. The future
versioned signature envelope must cover these same semantics and use the Castalia
signing key; a populated field is currently rejected. An unsigned receipt proves
internal consistency against trusted referenced commits, not authorship.

The secS schema-4 `packet_hash` is the hash of the entire bincode-serialized
ZenithPacket. It is not this command JSON digest. The receiver adapter uses its pinned native verification-only helper to
validate the signed context and exact packet/payload correspondence before binding
the command digest, operation, resource, manifest fingerprint, session and nonce.
Only receiver-pinned verifier keys may be trusted. Default-deny, deny-wins, expiry,
revocation, replay and production rejection of `local_dev_untrusted` are required;
native receiver fixtures pass, while live production signer/issuer and policy
qualification remain separate. The shipped runtime CLI defaults to deny-all.

Compatibility: this is a new explicit API boundary. It does not replace or reinterpret
persisted Hub v1 Case contracts. Legacy readers continue to read their exact stored
snapshots; migration must separately qualify eligibility, compare shadow output,
reconcile unknown effects and demonstrate reversible routing. Breaking schema
changes require a new contract version and consumer fixtures before deployment.
