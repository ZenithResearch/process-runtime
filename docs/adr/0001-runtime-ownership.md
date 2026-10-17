# 0001: Independently owned process execution

Decision recorded 2026-10-12 for Devgraph Task `runtime-contracts-ownership-adr`.
This implements the accepted ownership boundary; it does not select another tracker
or place operational data in Devgraph.

`process-runtime` owns reusable process drafts, immutable published versions and
compiled DAG snapshots, runs, step state, Attempts, leases, outputs, artifacts,
execution events, receipts, and its own inbox/outbox. A ProcessRun pins an exact
version and compilation hash for its entire lifetime. A non-service run has no
Service Request or Case prerequisite.

`service-management` owns intake Service Requests, managed service Cases, initial
Case plans, explicit CasePlanRevisions and its source outbox. Acceptance and
conversion are separate intentions. One Case may start multiple version-pinned
ProcessRuns. Service management stores references and rebuildable summaries; it
never owns runtime steps, Attempts, leases or outputs. A replacement run requires
an auditable revision and explicit validation of every carried output.

`frank` owns a deployable executor adapter and normalized dispatcher. Its configured
IntegrationAdapters own delivery lifecycle, provenance and diagnostics. Frank owns
its durable external-effect journal and provider correlation. The runtime separately
owns `RuntimeEffect`: its Attempt-scoped identity, fenced dispatch admission,
observed outcome and decisions to block completion, retry or recovery. Frank's
journal retains provider and exact-command evidence referring to that runtime
identity; it cannot author a canonical runtime effect outcome or complete work by
writing local delivery state. It never schedules process steps, mutates the
runtime store directly or treats a delivery acknowledgement as execution completion.

`hub` pins compatible components, supplies configuration and secret references,
wires endpoints, checks health and composes reversible routing. It defines no
canonical ServiceRequest, Case, ProcessRun or cross-database CaseRunBinding.
Existing Hub Case tables are legacy migration sources, not another owner of the
new greenfield aggregate. The legacy bridge must expose frozen snapshots,
eligibility and retained evidence until cutover; it cannot silently translate an
ordinal state into runtime success.

Devgraph owns implementation work and its workflow evidence. It is neither the
runtime database nor the owner of this runtime ontology. The machine-readable
owner/reference inventory is `contracts/ownership-v1.json`; each public state
object has exactly one owner. `runtime_records` accounts for every runtime
persistence kind, while `query_state_objects` identifies the source state exposed
by every public query. Runtime Attempt spans and service progress projections are
explicitly derived views, with their own schema owner and no independent execution
authority. A service runtime-handoff envelope belongs to the service source; the
runtime inbox and resulting run belong to the runtime. Optional originating request
and Case references never copy service aggregates into the runtime.

The initial implementation uses Python 3.12 with a modular application and explicit
persistence/authority ports. SQLite is the first adapter and has one writer,
explicit transactions and optimistic versions. Domain values import neither SQL
nor transport libraries. Postgres is an eventual adapter behind the same ports;
its migration and concurrency conformance tests belong to the storage Task.
There are no SLA clocks in the MVP.

Authentication evidence is separate from the Actor capability/directory value.
The runtime consumes verified secS context through an authority adapter, checks
receiver-local policy and current fences, and binds the complete command digest.
Matrix rooms, Hermes profiles and event-bus messages are delivery or provenance.
They confer no authentication identity, signing access or executor permission.

The operator approved a dedicated Frank identity with native Wallet file custody
on 2026-10-12. This decision does not claim an implemented generic machine identity
provisioner or unattended Wallet signing path. Wallet retains private key access;
Frank never loads a raw seed or obtains a generic signing oracle. Production must
remain closed until its actual supported signing and secS path is qualified.
