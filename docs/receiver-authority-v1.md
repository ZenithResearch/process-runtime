# Runtime receiver authority v1

The default runtime denies every command and query. Production wiring must supply a receiver-owned policy provider and an independently qualified native verifier binary; an HTTP caller cannot choose either. `LocalDevUntrustedVerifier` is an explicit development adapter with one configured subject. Production runtime construction prohibits enabling it.

`SecSExecutionAuthorityVerifier.verify(envelope, command, now_ms)` implements `ExecutionAuthorityVerifier`. The input snapshot is the closed `runtime.command.v1` or `runtime.query.v1` contract. The returned `VerifiedAuthority.operation` is the raw runtime operation, such as `executor.complete`; native descriptors and permission rules use the full `runtime.executor.complete.v1` name. The default receiver audience is `runtime://receiver-local`.

The authority envelope contains exactly `schema: runtime.secs-envelope.v1`, `packet_hex`, and `signed_context_hex`. Both hexadecimal values are lowercase encodings of the actual native fixed-integer bincode structs. The helper rejects trailing bytes, noncanonical reserialization, unrecognized fields and oversized input. There is no alternate signature-over-JSON protocol.

The receiver invokes `PublicVerifierKeyRegistry::verify_production_signed_context` from secS revision `11e7128e49c6df57f53e4c8b05e72d4bc78d798c`. It requires schema 4, Ed25519 node-and-verifier authentication, an active receiver-pinned public verifier key, the exact receiver audience, and exclusive expiry. It then checks the SHA-256 of the entire retained `ZenithPacket` against the signed `packet_hash`, packet/session/nonce/opcode equality, and the exact canonical request bytes against `packet.encrypted_payload`. This receiver profile carries the canonical runtime request in that native payload field; another transport representation requires an explicitly compatible adapter. The signed context lifetime is at most 60 seconds and must equal the packet claim TTL.

Python applies the receiver's current descriptor fingerprint and handler pin, the exact raw operation/opcode/resource/request digest binding, subject-key revocation and bounded permission rules. Configuration is reloaded for each verification. Rules specify one subject, one operation, explicit time bounds and an exact resource or an explicitly requested slash-terminated resource prefix. There are no wildcard rules; matching deny rules override matching allows. Missing keys, descriptors or allows deny access. The caller's Actor ID is not an authority identity: the application separately checks Actor ownership against the authenticated subject.

## Resources and opcodes

The authoritative closed opcode table is `authority.OPCODES`, tested against every command and query. Commands occupy `0x40` through `0x51`; queries occupy `0x60` through `0x69`. `attempt.get` is `0x69`. New operations require an explicit table entry and consumer fixture.

| Operation | Receiver resource |
| --- | --- |
| process.draft.put, process.publish, process.get | `processes/{process_id}` |
| version.get | `versions/{process_version}` |
| run.create, run.cancel, run.retry, run.get | `runs/{run_id}` |
| executor.* | `runs/{run_id}/steps/{step_id}` |
| actor.register, actor.advertise | `actors/{actor_id}` |
| work.list | `actors/{actor_id}/work` |
| artifact.put, artifact.get | `artifacts/{content_hash}` |
| receipt.get | `receipts/{receipt_id}` |
| output.get | `runs/{run_id}/steps/{step_id}/attempts/{attempt_id}/output` |
| attempt.get | `runs/{run_id}/steps/{step_id}/attempts/{attempt_id}` |
| effect.resolve, effect.get | `effects/{effect_id}` |
| events.list | `events`, or `runs/{run_id}/events` when run-filtered |
| handoff.consume | `handoffs/{sha256(canonical {source,event_id})}` |

`resource_for` derives this identity from validated payload fields. A command's declared resource must match it. The request digest binds every request field, including expected version, Attempt, fence, outputs and effect identity, even when the permission resource is broader than those fields.

## Transaction boundary

Cryptographic verification does not consume replay state. The runtime must verify current authority and time after acquiring its transaction, admit `(subject, session, opcode, nonce)` uniquely, enforce current lease/Attempt/fence and expected version, and commit replay, result, events and state atomically. Queries also consume replay state. An exact committed command result may be returned after current-authority revalidation before duplicate-nonce rejection; a different request cannot reuse the admitted replay tuple. All new request bodies must use a fresh nonce. This receiver helper has no replay database, issuer, key-custody, registry-management or grant-changing interface.

## Qualification and retained evidence

The wrapper and its synthetic fixtures demonstrate native receiver verification compatibility only. Their passing tests do not qualify an installed native Wallet/secS stack, unattended issuer, generic security-stack migration, Frank machine identity or real credential custody. Nothing here installs or activates native authority. The historical secS source revision is a pinned verification substrate; no historical application-specific signer is re-enabled.

The native helper binary is selected by an absolute operator-owned path and an expected SHA-256 checked on each invocation. Its file and ancestor directories must remain operator-controlled. The Python wrapper clears its subprocess environment and applies a five-second timeout. Deployment must separately provide the approved binary hash, receiver descriptors, current public verifier pins, subject revocations and scoped permissions. No such live configuration is included.

See `native/secs-verifier/README.md` for the offline build and isolated tests. Retained public synthetic packet/context fixtures are in `tests/fixtures/authority/native-secs-v4.json`; their source requests are in `native-fixture-input.json`. The fixed test signer exists only under Rust `#[cfg(test)]` and has no live authority. Do not configure its public key as a production trust root.

## Receiver-owned CLI configuration

The CLI accepts `--receiver-config /absolute/private/receiver.json`. This is an
operator file, never an HTTP request field or a discovered trust registry. Omitting
it keeps default-deny authority. An explicitly missing, malformed, empty, shared,
linked or unsafe configuration rejects startup before opening the runtime store.
The flag cannot be combined with local development authority; production rejects
`--local-dev-untrusted` independently. `--admission-policy` still controls new-run
admission, and an explicitly empty path is rejected instead of selecting a default.

The closed configuration contains exactly:

```json
{
  "schema": "runtime.receiver-configuration.v1",
  "audience": "runtime://receiver-local",
  "native_verifier": {
    "executable": "/absolute/operator-controlled/process-runtime-secs-verifier",
    "sha256": "<exact reviewed lowercase SHA-256>"
  },
  "policy_file": "/absolute/private/runtime-receiver-policy.json"
}
```

Configuration and public policy files must be regular files with one link, owned
by the runtime operator, with no group/other permissions, inside an owner-private
directory. Paths are absolute and cannot traverse symlinks or writable/uncontrolled
ancestors. Root-owned sticky temporary roots are allowed for isolated fixtures.
The pinned helper must be executable, owned by root or the operator, and unwritable
to peers. Its path and SHA-256 are checked at startup and each invocation. The
existing verification-only helper and native schema-4 protocol remain unchanged.

The separately reloadable policy contains exactly `schema:
"runtime.receiver-policy.v1"`, `audience`, `keys`, `descriptors`, `permissions` and
`revoked_subject_keys`. Each key contains `key_id`, `public_key_hex`, `status`,
`production_authority`, `not_before`, `not_after` and `revoked_at`; optional windows
are represented explicitly by null and otherwise use Unix seconds. Key identities
must be unique. A descriptor contains the full `operation`, exact `fingerprint` and
`handler_id`. A permission contains `subject_id`, full `operation`, `resource`,
`effect`, `not_before_ms`, `not_after_ms`, `resource_match`, `key_id` and `active`.
An explicit null `key_id` permits authenticated keys for that named subject; an
exact key ID narrows the rule. A revocation contains `subject_id` and `key_id`.
All objects reject unknown fields and all lists are bounded. Empty keys or grants
remain default-deny. Never place a private key, seed, token or signing command here.

Public keys, descriptor pins, permissions and revocations reload for every
verification inside runtime transaction admission. A policy change during native
verification rejects before verified authority is returned. Effective verified
call expiry is capped by the native context, current matching allow windows, an
impending matching deny start and the actual verifier signing key's expiry or
revocation time. The kernel's post-verifier clock check therefore rejects local
permissions or keys that expire while the native helper runs. This narrows local
admission; it does not change the signed native packet/context semantics.
Operator policy updates
should replace the complete private file atomically; invalid intermediate or missing
files deny calls and degrade verification availability. Changing the startup helper
pin, policy path or audience requires restart. Historical receipt/state ownership is
unaffected by public policy rotation.

`/ready` retains storage and admission checks. A configured verifier reports
`authority: "configured_native_unqualified"`, `verification: "available"` or
`"unavailable"`, and `qualification: "unqualified"`, with ready false and HTTP 503.
Valid public configuration and matching helper bytes establish availability to
check this cryptographic profile; they do not qualify the installed Wallet/secS
release, native issuer, custody, result attestation or deployed authority chain.
The internal verified-call mode `production_verified` identifies the required
signature profile and does not promote this readiness or assert release admission.
No caller or configuration boolean can turn qualification into ready.

Isolated CLI tests use freshly signed public packets from the same pinned native
Rust types and the already-public synthetic test signer. The generator is retained
only under the temporary evidence directory and is excluded from runtime/native
release packages. Its public key is used solely in temporary test policy; it must
never be a production trust root. No live custody, grant, signer or trust state is
created or changed by these tests.

## Native descriptor fingerprint compatibility

After the pinned helper authenticates the exact signed context, the receiver
accepts either the existing lowercase 64-hex descriptor digest or Native’s exact
`descriptor:sha256:<digest>` representation, provided that digest equals the
current receiver-owned descriptor pin. Other prefixes, spelling, case, lengths
and digests deny. Runtime normalizes this authenticated binding to its existing
internal digest field; the original context and signature bytes remain intact.
Service uses the same exact comparison without changing its internal call wire.
This is additive compatibility with the existing schema-4 verifier, not a new
signature format, trust source, policy grant or installed qualification.
