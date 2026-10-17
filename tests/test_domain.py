from dataclasses import FrozenInstanceError, replace
import unittest

from process_runtime.domain import (
    Actor, ArtifactRef, Attempt, AttemptState, CompiledProcess, DomainError,
    Lease, OutputCommit, ProcessDefinition, ProcessPin, ProcessRun, ProcessVersion,
    Receipt, RunState, Snapshot, StepRun, StepState, canonical, sha256, transition,
)


class RuntimeInvariantTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = Snapshot.of({"process_id": "development", "steps": [{"step_id": "verify"}]})
        self.compiled = CompiledProcess("development", self.snapshot, self.snapshot.digest)
        self.version = ProcessVersion("development-v1", 1, self.compiled, 1, 1000)
        self.pin = ProcessPin.of(self.version)
        self.attempt = Attempt("attempt-1", "run-1", "verify", 1, "actor-1", Snapshot.of({}).digest, 4, 1000)
        self.lease = Lease("run-1", "verify", "attempt-1", "actor-1", 4, 2000)

    def test_caller_mutations_cannot_change_frozen_plan_or_inputs(self):
        mutable = {"process_id": "development", "steps": [{"step_id": "verify"}]}
        retained = Snapshot.of(mutable)
        mutable["steps"][0]["step_id"] = "changed"
        retained.value["steps"][0]["step_id"] = "also-changed"
        self.assertEqual(retained, self.snapshot)
        with self.assertRaises(FrozenInstanceError):
            self.version.ordinal = 2

    def test_edited_draft_does_not_repin_active_run(self):
        definition = ProcessDefinition("development", 1, self.snapshot, Snapshot.of({"source": "doc-v1"}))
        run = ProcessRun("run-1", self.pin, Snapshot.of({}))
        revised = definition.revise(expected_revision=1, draft=Snapshot.of({"process_id": "development", "steps": []}), provenance=Snapshot.of({"source": "doc-v2"}))
        self.assertEqual(revised.process_id, definition.process_id)
        self.assertEqual(revised.revision, 2)
        self.assertEqual(run.pin.compilation_hash, self.snapshot.digest)
        self.assertNotEqual(run.pin.compilation_hash, revised.draft.digest)
        with self.assertRaises(DomainError):
            definition.revise(expected_revision=2, draft=revised.draft, provenance=revised.provenance)

    def test_draft_identity_cannot_move_to_another_process(self):
        provenance = Snapshot.of({"source": "retained-document"})
        with self.assertRaises(DomainError) as caught:
            ProcessDefinition("other-process", 1, self.snapshot, provenance)
        self.assertEqual(caught.exception.code, "process_mismatch")
        definition = ProcessDefinition("development", 1, self.snapshot, provenance)
        with self.assertRaises(DomainError):
            definition.revise(expected_revision=1,
                              draft=Snapshot.of({"process_id": "other-process", "steps": []}),
                              provenance=provenance)
        self.assertEqual(definition.revision, 1)
        self.assertEqual(definition.draft, self.snapshot)
        for value in ([], {}, None):
            with self.subTest(value=value), self.assertRaises(DomainError):
                ProcessDefinition("development", 1, Snapshot.of(value), provenance)

    def test_actor_malformed_entries_fail_as_domain_errors(self):
        for invalid in ({"capability": "review"}, ["review"], True, None):
            for field in ("capabilities", "resources"):
                kwargs = {"actor_id": "worker", "capabilities": ()}
                kwargs[field] = (invalid,)
                with self.subTest(field=field, invalid=invalid), self.assertRaises(DomainError):
                    Actor(**kwargs)

    def test_run_origin_matches_the_existing_public_bound(self):
        # Service provenance remains an opaque reference, with no copied Case.
        from process_runtime.contracts import validate
        for length in (1, 513, 4096):
            reference = "x" * length
            run = ProcessRun("run-1", self.pin, Snapshot.of({}), source_ref=reference)
            command = {"schema": "runtime.command.v1", "operation": "run.create",
                       "request_id": "create", "resource": "runs/run-1", "expected_version": None,
                       "payload": {"run_id": run.run_id,
                                   "pin": {"process_id": self.pin.process_id,
                                           "process_version": self.pin.process_version,
                                           "compilation_hash": self.pin.compilation_hash},
                                   "inputs": {}, "source_ref": reference}}
            validate(command, "command")
            self.assertEqual(run.source_ref, reference)
        for invalid in ("", "x" * 4097):
            with self.subTest(length=len(invalid)), self.assertRaises(DomainError):
                ProcessRun("run-1", self.pin, Snapshot.of({}), source_ref=invalid)

    def test_compilation_hash_and_process_ownership_cannot_disagree(self):
        with self.assertRaises(DomainError):
            CompiledProcess("development", self.snapshot, "0" * 64)
        with self.assertRaises(DomainError):
            CompiledProcess("service-review", self.snapshot, self.snapshot.digest)

    def test_terminal_attempts_never_reopen_or_change_outcome(self):
        for outcome in AttemptState:
            if outcome == AttemptState.ACTIVE:
                continue
            ended = self.attempt.move(outcome)
            for other in AttemptState:
                with self.subTest(outcome=outcome, other=other), self.assertRaises(DomainError):
                    ended.move(other)
        retry = replace(self.attempt, attempt_id="attempt-2", ordinal=2, fence=5, started_at_ms=2001)
        self.assertNotEqual(self.attempt.attempt_id, retry.attempt_id)
        with self.assertRaises(DomainError):
            self.lease.require_current(retry, now_ms=2100, current_fence=5)

    def test_terminal_runs_and_steps_do_not_silently_restart(self):
        for state, targets in [(RunState.SUCCEEDED, RunState), (RunState.FAILED, RunState), (RunState.CANCELLED, RunState),
                               (StepState.SUCCEEDED, StepState), (StepState.FAILED, StepState), (StepState.CANCELLED, StepState)]:
            for target in targets:
                with self.subTest(state=state, target=target), self.assertRaises(DomainError):
                    transition(state, target)

    def test_run_path_is_neutral_and_explicit(self):
        run = ProcessRun("development-run", self.pin, Snapshot.of({}))
        self.assertIsNone(run.source_ref)  # No ServiceRequest or Case required.
        with self.assertRaises(DomainError):
            run.move(RunState.SUCCEEDED)
        run = run.move(RunState.RUNNING).move(RunState.BLOCKED).move(RunState.RUNNING).move(RunState.SUCCEEDED)
        self.assertEqual(run.version, 5)
        for target in ("running", AttemptState.ACTIVE, StepState.RUNNING):
            with self.assertRaises(DomainError):
                transition(RunState.PENDING, target)

    def test_running_step_needs_attempt_and_fence(self):
        for fields in ({}, {"fence": 1}, {"current_attempt": "attempt-1"}):
            with self.subTest(fields=fields), self.assertRaises(DomainError):
                StepRun("run-1", "verify", StepState.RUNNING, **fields)
        self.assertEqual(StepRun("run-1", "verify", StepState.RUNNING, 4, "attempt-1").fence, 4)

    def test_lease_rejects_each_changed_binding_and_boundary_expiry(self):
        self.lease.require_current(self.attempt, now_ms=1000, current_fence=4)
        for field, value in {"run_id": "other", "step_id": "other", "attempt_id": "other", "actor_id": "other", "fence": 5}.items():
            with self.subTest(field=field), self.assertRaises(DomainError):
                replace(self.lease, **{field: value}).require_current(self.attempt, now_ms=1500, current_fence=4)
        for now in (999, 2000, 2001, True):
            with self.subTest(now=now), self.assertRaises(DomainError):
                self.lease.require_current(self.attempt, now_ms=now, current_fence=4)
        with self.assertRaises(DomainError):
            self.lease.require_current(self.attempt.move(AttemptState.FAILED), now_ms=1500, current_fence=4)

    def test_outputs_are_immutable_and_bound_to_exact_attempt(self):
        values = Snapshot.of({"passed": True})
        commit = OutputCommit("commit-1", "run-1", "verify", "attempt-1", 4, values, values.digest, 1700)
        commit.require_attempt(self.attempt)
        with self.assertRaises(DomainError):
            commit.require_attempt(replace(self.attempt, attempt_id="attempt-2"))
        with self.assertRaises(DomainError):
            replace(commit, output_digest="0" * 64)
        with self.assertRaises(DomainError):
            replace(commit, values=Snapshot.of([]))

    def test_receipt_cannot_claim_success_before_output_or_signature_verification(self):
        values = dict(receipt_id="receipt-1", pin=self.pin, run_id="run-1", step_id="verify", attempt_id="attempt-1",
                      actor_id="actor-1", input_digest=self.attempt.input_digest, output_digest=None, fence=4,
                      started_at_ms=1000, recorded_at_ms=1700, outcome=AttemptState.SUCCEEDED)
        with self.assertRaises(DomainError):
            Receipt(**values)
        values["output_digest"] = Snapshot.of({}).digest
        receipt = Receipt(**values)
        for change in ({"recorded_at_ms": 999}, {"outcome": AttemptState.ACTIVE}, {"signature": Snapshot.of({"unverified": "signature"})}):
            with self.subTest(change=change), self.assertRaises(DomainError):
                replace(receipt, **change)

    def test_content_addressed_artifacts_reject_changed_bytes_or_size(self):
        content = b"test evidence\n"
        reference = ArtifactRef(sha256(content), len(content), "text/plain")
        reference.verify(content)
        for changed in (b"test Evidence\n", content + b"!", content[:-1]):
            with self.subTest(changed=changed), self.assertRaises(DomainError):
                reference.verify(changed)

    def test_actor_capability_is_not_authentication_identity(self):
        actor = Actor("reviewer", ("review",), ("workspace",), "rolodex-person")
        self.assertEqual(actor.missing(("review",), ("workspace",)), ())
        self.assertEqual(actor.missing(("deploy",), ("production",)), ("capability:deploy", "resource:production"))
        self.assertFalse(hasattr(actor, "public_key"))
        self.assertFalse(hasattr(actor, "subject_id"))
        for capabilities in (("review", "review"), ["review"]):
            with self.assertRaises(DomainError):
                Actor("reviewer", capabilities)

    def test_canonical_json_rejects_nonfinite_and_ambiguous_shapes(self):
        for value in (float("nan"), float("inf"), {1: "not-a-string-key"}, ("not", "a", "list")):
            with self.subTest(value=value), self.assertRaises(DomainError):
                canonical(value)
        for text in ('{"a":1,"a":2}', '{"a": 1}', '{"n":NaN}'):
            with self.subTest(text=text), self.assertRaises(DomainError):
                Snapshot(text)
        self.assertEqual(Snapshot.of({"b": 2, "a": [1, True]}).digest, Snapshot.of({"a": [1, True], "b": 2}).digest)


class UnicodeBoundaryTests(unittest.TestCase):
    def test_invalid_unicode_and_depth_fail_as_domain_errors(self):
        for value in ({"x": "\ud800"}, {"\udfff": 1}):
            with self.assertRaises(DomainError):
                Snapshot.of(value)
        circular = []; circular.append(circular)
        with self.assertRaises(DomainError):
            Snapshot.of(circular)

if __name__ == "__main__":
    unittest.main()
