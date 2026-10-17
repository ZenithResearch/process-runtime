from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import unittest

from process_runtime.authority import (
    DEFAULT_AUDIENCE, OPCODES, DenyAllVerifier, LocalDevUntrustedVerifier,
    NativeSecSHelper, PermissionRule, ReceiverPolicy, SecSExecutionAuthorityVerifier,
    VerifierKey, authorize_binding, local_dev_envelope, operation_name, resource_for,
)
from process_runtime.contracts import COMMANDS, QUERIES, validate
from process_runtime.domain import DomainError, Snapshot
from process_runtime.ports import VerifiedAuthority

ROOT = Path(__file__).resolve().parents[1]


def query(operation="run.get", payload=None):
    return validate({"schema": "runtime.query.v1", "operation": operation,
                     "payload": payload or {"run_id": "run-1"}}, "query")


def binding(request, mode="production_verified"):
    return VerifiedAuthority("subject", "holder", DEFAULT_AUDIENCE, request.value["operation"],
        resource_for(request), request.digest, 1000000, 1060000, "01" * 16,
        OPCODES[request.value["operation"]], "02" * 12, "a" * 64, mode)


class AuthorityBindingTests(unittest.TestCase):
    def test_opcode_contract_is_closed_unique_and_covers_all_commands_and_queries(self):
        self.assertEqual(set(OPCODES), set(COMMANDS) | set(QUERIES))
        self.assertEqual(len(OPCODES), len(set(OPCODES.values())))
        self.assertTrue(all(0x40 <= opcode <= 0xFF for opcode in OPCODES.values()))

    def test_resource_projection_covers_all_fixtures_with_explicit_payload_identity(self):
        fixtures = json.loads((ROOT / "contracts/consumer-fixtures-v1.json").read_text())
        for kind, examples in (("command", fixtures["commands"]), ("query", fixtures["queries"])):
            for example in examples:
                request = validate(example, kind)
                resource = resource_for(request)
                self.assertTrue(resource)
                self.assertEqual(operation_name(request), "runtime." + example["operation"] + ".v1")
                if kind == "command":
                    corrected = deepcopy(example); corrected["resource"] = resource
                    request = validate(corrected, kind)
                authorize_binding(binding(request), request, 1001000)

    def test_exact_query_resources_and_handoff_digest(self):
        self.assertEqual(resource_for(query()), "runs/run-1")
        self.assertEqual(resource_for(query("events.list", {"after": 0, "limit": 5})), "events")
        self.assertEqual(resource_for(query("events.list", {"after": 0, "limit": 5, "run_id": "r"})), "runs/r/events")
        self.assertEqual(resource_for(query("output.get", {"run_id": "r", "step_id": "s", "attempt_id": "a"})), "runs/r/steps/s/attempts/a/output")
        self.assertEqual(resource_for(query("attempt.get", {"run_id": "r", "step_id": "s", "attempt_id": "a"})), "runs/r/steps/s/attempts/a")
        fixtures = json.loads((ROOT / "contracts/consumer-fixtures-v1.json").read_text())
        body = deepcopy(next(c for c in fixtures["commands"] if c["operation"] == "handoff.consume"))
        expected = Snapshot.of({"source": body["payload"]["source"], "event_id": body["payload"]["event_id"]}).digest
        self.assertEqual(resource_for(validate(body, "command")), "handoffs/" + expected)

    def test_binding_rejects_every_substituted_field_and_expiry_boundary(self):
        request = query(); original = binding(request)
        for field, value in {"operation": "process.get", "resource": "runs/other", "request_digest": "0" * 64,
            "audience": "other", "opcode": 64, "session_id": "bad", "nonce": "bad",
            "descriptor_fingerprint": "bad", "key_id": "", "subject_id": "", "issued_at_ms": True,
            "expires_at_ms": 1100000, "mode": "local_dev_untrusted"}.items():
            with self.subTest(field=field), self.assertRaises(DomainError):
                authorize_binding(replace(original, **{field: value}), request, 1001000)
        for now in (999999, 1060000, 1060001, True):
            with self.subTest(now=now), self.assertRaises(DomainError):
                authorize_binding(original, request, now)

    def test_command_resource_is_derived_not_trusted_from_caller(self):
        body = {"schema": "runtime.command.v1", "operation": "run.cancel", "request_id": "cancel-1",
                "resource": "runs/other", "expected_version": 1, "payload": {"run_id": "run-1", "reason": "stop"}}
        request = validate(body, "command")
        with self.assertRaises(DomainError):
            authorize_binding(binding(request), request, 1001000)

    def test_default_adapters_deny_and_development_cannot_claim_production_identity(self):
        request = query()
        for verifier in (DenyAllVerifier(), SecSExecutionAuthorityVerifier()):
            with self.assertRaises(DomainError):
                verifier.verify(envelope=b"{}", command=request, now_ms=1001000)
        verifier = LocalDevUntrustedVerifier("configured-subject")
        envelope = local_dev_envelope(request, now_ms=1000000, session_id="01" * 16, nonce="02" * 12)
        verified = verifier.verify(envelope=envelope, command=request, now_ms=1001000)
        self.assertEqual(verified.subject_id, "configured-subject")
        self.assertEqual(verified.mode, "local_dev_untrusted")
        with self.assertRaises(DomainError):
            authorize_binding(verified, request, 1001000)
        authorize_binding(verified, request, 1001000, allow_local_dev=True)
        forged = json.loads(envelope); forged["subject_id"] = "administrator"
        with self.assertRaises(DomainError):
            verifier.verify(envelope=json.dumps(forged).encode(), command=request, now_ms=1001000)

    def test_malformed_development_envelope_rejects_duplicates_and_nonfinite_fields(self):
        verifier = LocalDevUntrustedVerifier("subject")
        for envelope in (b'{"nonce":"a","nonce":"b"}', b'{"expires_at_ms":NaN}', b'[]', b'\xff'):
            with self.subTest(envelope=envelope), self.assertRaises(DomainError):
                verifier.verify(envelope=envelope, command=query(), now_ms=1001000)


class ReceiverPermissionTests(unittest.TestCase):
    def rule(self, effect="allow", **changes):
        return replace(PermissionRule("subject", "runtime.run.get.v1", "runs/run-1", effect, 1000, 2000), **changes)

    def policy(self, rules=(), revoked=frozenset()):
        return ReceiverPolicy(DEFAULT_AUDIENCE, (), (), tuple(rules), revoked)

    def test_default_deny_deny_wins_and_exact_key_scope(self):
        for rules in ((), (self.rule("deny"),), (self.rule(), self.rule("deny")),
                      (self.rule(key_id="other"),), (self.rule(active=False),)):
            with self.subTest(rules=rules), self.assertRaises(DomainError):
                self.policy(rules).require_permission("subject", "holder", "runtime.run.get.v1", "runs/run-1", 1500)
        self.policy((self.rule(key_id="holder"),)).require_permission("subject", "holder", "runtime.run.get.v1", "runs/run-1", 1500)

    def test_rule_time_revocation_and_explicit_prefix_boundaries(self):
        policy = self.policy((self.rule(resource="runs/run-1/", resource_match="prefix"),))
        policy.require_permission("subject", "holder", "runtime.run.get.v1", "runs/run-1/steps/check", 1500)
        for resource in ("runs/run-10/steps/check", "runs/run-1"):
            with self.assertRaises(DomainError):
                policy.require_permission("subject", "holder", "runtime.run.get.v1", resource, 1500)
        for now in (999, 2000):
            with self.assertRaises(DomainError):
                self.policy((self.rule(),)).require_permission("subject", "holder", "runtime.run.get.v1", "runs/run-1", now)
        with self.assertRaises(DomainError):
            self.policy((self.rule(),), frozenset({("subject", "holder")})).require_permission("subject", "holder", "runtime.run.get.v1", "runs/run-1", 1500)

    def test_configuration_rejects_wildcards_and_implicit_unbounded_grants(self):
        for change in ({"subject_id": "*"}, {"operation": "*"}, {"resource": "runs/*"},
                       {"resource": "runs", "resource_match": "prefix"}, {"not_after_ms": 1000}):
            with self.subTest(change=change), self.assertRaises((DomainError, ValueError)):
                self.rule(**change)


class AuthenticatedDescriptorFingerprintTests(unittest.TestCase):
    """Boundary projection after the pinned native helper authenticates schema4."""
    def setUp(self):
        self.request = query()
        self.context = {"schema_version": 4, "subject": {"subject_id": "subject", "key_id": "holder"},
            "audience": DEFAULT_AUDIENCE, "operation": operation_name(self.request),
            "resource": resource_for(self.request), "descriptor_fingerprint": "a" * 64,
            "handler_id": "runtime-v1", "replay_scope": "session:opcode:nonce",
            "issued_at": 1000, "expires_at": 1060, "session_id": [1] * 16,
            "nonce": [2] * 12, "opcode": OPCODES["run.get"]}
        context = self.context
        class AuthenticatedOutputFixture:
            def verify(inner, value):
                return {"context": context, "signer_key_id": "fixture",
                        "authenticator_kind": "ed25519_node_and_verifier"}
        policy = ReceiverPolicy(DEFAULT_AUDIENCE,
            (VerifierKey("fixture", "a" * 64),),
            ((operation_name(self.request), "a" * 64, "runtime-v1"),),
            (PermissionRule("subject", operation_name(self.request), resource_for(self.request), "allow", 999000, 1200000),))
        self.verifier = SecSExecutionAuthorityVerifier(AuthenticatedOutputFixture(), lambda: policy)
        self.envelope = Snapshot.of({"schema": "runtime.secs-envelope.v1", "packet_hex": "00", "signed_context_hex": "00"}).text.encode()

    def verify(self):
        return self.verifier.verify(envelope=self.envelope, command=self.request, now_ms=1001000)

    def test_native_prefix_and_legacy_digest_bind_the_same_current_descriptor(self):
        for value in ("a" * 64, "descriptor:sha256:" + "a" * 64):
            with self.subTest(fingerprint=value):
                self.context["descriptor_fingerprint"] = value
                self.assertEqual(self.verify().descriptor_fingerprint, "a" * 64)
                self.assertEqual(self.context["descriptor_fingerprint"], value)

    def test_only_the_exact_current_native_prefix_is_admitted(self):
        for value in ("descriptor:sha256:" + "b" * 64, "descriptor:SHA256:" + "a" * 64,
                      "descriptor:sha256:" + "A" * 64, "descriptor:sha256:" + "a" * 63,
                      "descriptor:sha256:" + "a" * 64 + " ", ["a" * 64], None):
            with self.subTest(fingerprint=value), self.assertRaises(DomainError):
                self.context["descriptor_fingerprint"] = value
                self.verify()


@unittest.skipUnless(os.environ.get("PROCESS_RUNTIME_NATIVE_VERIFIER"), "Build the pinned verification-only Rust helper and set PROCESS_RUNTIME_NATIVE_VERIFIER")
class NativeSecSAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = Path(os.environ["PROCESS_RUNTIME_NATIVE_VERIFIER"])
        cls.helper = NativeSecSHelper(cls.binary, hashlib.sha256(cls.binary.read_bytes()).hexdigest())
        data = json.loads((ROOT / "tests/fixtures/authority/native-secs-v4.json").read_text())
        cls.fixtures = {item["name"]: item for item in data["fixtures"]}

    def policy(self, fixture):
        request = Snapshot(fixture["request"])
        return ReceiverPolicy(DEFAULT_AUDIENCE,
            (VerifierKey("synthetic-verifier", fixture["public_key_hex"], not_before=999, not_after=1200),),
            ((operation_name(request), "a" * 64, "runtime-v1"),),
            (PermissionRule("synthetic-subject", operation_name(request), resource_for(request), "allow", 999000, 1200000),))

    def verify(self, fixture, policy=None, request=None, now_ms=1001000):
        return SecSExecutionAuthorityVerifier(self.helper, lambda: policy or self.policy(fixture)).verify(
            envelope=Snapshot.of(fixture["envelope"]).text.encode(),
            command=request or Snapshot(fixture["request"]), now_ms=now_ms)

    def test_native_command_and_query_signatures_verify_with_exact_packet_binding(self):
        for name in ("command", "query"):
            fixture = self.fixtures[name]
            authority = self.verify(fixture)
            self.assertEqual(authority.mode, "production_verified")
            self.assertEqual(authority.operation, Snapshot(fixture["request"]).value["operation"])
            self.assertEqual(authority.request_digest, Snapshot(fixture["request"]).digest)

    def test_signed_wrong_operation_resource_and_opcode_are_rejected_by_receiver(self):
        for name in ("wrong-operation", "wrong-resource", "wrong-opcode"):
            with self.subTest(name=name), self.assertRaises(DomainError):
                self.verify(self.fixtures[name])

    def test_any_signature_packet_or_request_substitution_is_rejected(self):
        original = self.fixtures["command"]
        for field in ("signed_context_hex", "packet_hex"):
            fixture = deepcopy(original)
            raw = bytearray.fromhex(fixture["envelope"][field]); raw[-1] ^= 1
            fixture["envelope"][field] = raw.hex()
            with self.subTest(field=field), self.assertRaises(DomainError):
                self.verify(fixture)
        for field, value in (("fence", 2), ("attempt_id", "other-attempt"), ("outputs", {"passed": False})):
            request = Snapshot(original["request"]).value; request["payload"][field] = value
            with self.subTest(field=field), self.assertRaises(DomainError):
                self.verify(original, request=Snapshot.of(request))

    def test_key_revocation_expiry_audience_and_descriptor_changes_are_current(self):
        fixture = self.fixtures["command"]; policy = self.policy(fixture)
        policies = [replace(policy, keys=()), replace(policy, audience="runtime://other"),
            replace(policy, keys=(replace(policy.keys[0], status="revoked"),)),
            replace(policy, keys=(replace(policy.keys[0], not_after=1001),)),
            replace(policy, keys=(replace(policy.keys[0], production_authority=False),)),
            replace(policy, descriptors=((policy.descriptors[0][0], "b" * 64, "runtime-v1"),)),
            replace(policy, revoked_subject_keys=frozenset({("synthetic-subject", "synthetic-holder")})),
            replace(policy, rules=(replace(policy.rules[0], effect="deny"),))]
        for current in policies:
            with self.subTest(policy=current), self.assertRaises(DomainError):
                self.verify(fixture, policy=current)
        for now in (999000, 1060000):
            with self.assertRaises(DomainError):
                self.verify(fixture, now_ms=now)

    def test_policy_reloaded_each_call_and_native_binary_hash_is_pinned(self):
        fixture = self.fixtures["query"]; current = [self.policy(fixture)]
        verifier = SecSExecutionAuthorityVerifier(self.helper, lambda: current[0])
        kwargs = dict(envelope=Snapshot.of(fixture["envelope"]).text.encode(), command=Snapshot(fixture["request"]), now_ms=1001000)
        verifier.verify(**kwargs)
        current[0] = replace(current[0], rules=())
        with self.assertRaises(DomainError):
            verifier.verify(**kwargs)
        bad = SecSExecutionAuthorityVerifier(NativeSecSHelper(self.binary, "0" * 64), lambda: self.policy(fixture))
        with self.assertRaises(DomainError):
            bad.verify(**kwargs)


if __name__ == "__main__":
    unittest.main()
