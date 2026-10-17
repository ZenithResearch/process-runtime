# process-runtime

An independently owned Python 3.12 runtime for reusable, typed processes. It owns drafts, immutable compiled versions, pinned runs, dependency readiness, fenced Attempts and leases, outputs, artifacts, receipts, effects, inbox/outbox and canonical events. Service Requests and Cases belong to service-management. Hub composes components; Frank uses the public executor protocol.

The SQLite adapter admits one writer process and commits state, outputs, receipts, audit, replay and exact request results atomically. Markdown/text authoring accepts an explicit `process-json` block; parser uncertainty blocks publication. The compiler rejects invalid DAGs and incompatible bindings. Scheduler decisions use only the pinned DAG and committed dependency outputs.

## Local verification

```sh
python3.12 -m venv .venv
.venv/bin/pip install -e .
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

Native receiver tests require the pinned verification-only Rust helper; see [native verification](native/secs-verifier/README.md). They explicitly skip when it is unavailable. Isolated native source verification does not qualify replacing the live Wallet/secS stack or provisioning Frank's production identity.

Start an explicitly untrusted development instance in an owner-private directory:

```sh
mkdir -m 700 /tmp/process-runtime-development
.venv/bin/python -m process_runtime --database /tmp/process-runtime-development/runtime.db \
  --environment development --local-dev-untrusted
```

Without the development opt-in, production authority defaults to deny. The production composition still needs an operator-qualified signer/issuer and receiver policy; no raw key is read by this runtime or its public client. The separate native helper verifies signed schema-4 contexts and exact packet bytes only.

## Public clients and documentation

`process_runtime_client` is the wire-only package imported by consumers. It includes generated typed payloads/methods, contract validation, canonical resource derivation, exact retry helpers and explicit transport ambiguity. It never imports runtime implementation modules. Regenerate using `scripts/export_contract.py` and `scripts/export_client.py`.

- [API and executor semantics](docs/api-and-executor-v1.md)
- [Storage, recovery and PostgreSQL conformance boundary](docs/storage-and-recovery.md)
- [Receiver authority and native provenance](docs/receiver-authority-v1.md)
- [Native request and transport byte budgets](docs/native-transport-budget-v1.md)
- [Ownership ADR](docs/adr/0001-runtime-ownership.md)
- [Canonical wire schema](contracts/runtime-v1.schema.json) and [OpenAPI](contracts/openapi-v1.json)

Canonical command/query envelopes admit at most 2 MiB. Compiler documents and typed input values retain their 1 MiB limits, and result/output limits remain independent. Native Packet, proof, context, helper and escaped HTTP budgets are separately bounded; each HTTP server admits two request bodies with an absolute five-second read deadline. These transport changes do not qualify an authority chain.

Tests cover publication, typed scheduling, concurrent claims, stale fencing, retry Attempts, process death around transaction commit, restart idempotency, effect ambiguity, inbox/outbox delivery, HTTP loss, replay/authorization, and receipt-chain tampering. Acknowledgement never completes an effect. Already successful effects whose outputs were lost remain blocked; an explicit future recovery contract is required to carry them forward safely.

Implementation evidence is local preparation against the Devgraph Tasks. Live workflow status and production qualification must be reported separately; neither is inferred from passing tests.

Built wheels include the reviewed process resources and source provenance under the installation prefix at `share/process-runtime/resources/`. These are authoring inputs for explicit publication; installing a package does not automatically publish or run a process.

## Public deployment

Use the [Zenith Hub lightweight deployer](https://github.com/ZenithResearch/zenith-hub-lightweight)
for the shared Apple-silicon Mac installer and operator UI. Component source lives
under [ZenithResearch](https://github.com/ZenithResearch). Installation does not
provision native identities, grant command authority, or enable external effects.
See `NOTICE.public-baseline.md` for the scope of this clean publication.
