"""Verify unsigned execution consistency against trusted runtime records.

Unsigned receipts are integrity envelopes, not an independently authenticated
claim. Callers obtain the version, Attempt and output through a trusted runtime
query path; comparing mutually replaced untrusted objects proves nothing.
"""
from .compiler import validate_values
from .contracts import validate
from .domain import DomainError, Snapshot


def verify_receipt(receipt: dict, *, version: dict, attempt: dict, output: dict | None) -> Snapshot:
    retained = validate(receipt, "receipt")
    def require(condition):
        if not condition:
            raise DomainError("incompatible_version", "Receipt does not match its trusted execution chain")
    pin = version["pin"]
    require(Snapshot.of(version["compiled"]).digest == pin["compilation_hash"])
    require(receipt["pin"] == pin == attempt["pin"])
    require(all(receipt[key] == attempt[key] for key in ("run_id", "step_id", "attempt_id", "actor_id", "fence", "started_at_ms")))
    require(receipt["recorded_at_ms"] >= receipt["started_at_ms"])
    require(receipt["outcome"] == attempt["state"] and receipt["input_digest"] == attempt["input_digest"])
    require(Snapshot.of(attempt["inputs"]).digest == receipt["input_digest"])
    specs = {step["step_id"]: step for step in version["compiled"]["steps"]}
    require(receipt["step_id"] in specs)
    spec = specs[receipt["step_id"]]
    validate_values(attempt["inputs"], spec["inputs"])
    if receipt["outcome"] == "succeeded":
        require(output is not None)
        require(all(output[key] == receipt[key] for key in ("pin", "run_id", "step_id", "attempt_id", "actor_id", "fence", "receipt_id")))
        require(output["inputs_digest"] == receipt["input_digest"])
        require(output["output_types"] == spec["outputs"])
        values = validate_values(output["outputs"], spec["outputs"])
        require(values.digest == output["output_digest"] == receipt["output_digest"])
        require(receipt["started_at_ms"] <= output["committed_at_ms"] <= receipt["recorded_at_ms"])
    else:
        require(output is None and receipt["output_digest"] is None)
    return retained
