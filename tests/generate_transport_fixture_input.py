"""Public Python producer vectors; native signatures exist only in Rust cfg(test).

argv1: native test generator input; optional argv2: exact request vectors+hash manifest.
No authority or private signing material is created here.
"""

import hashlib, json
from pathlib import Path
import sys
from test_transport_budget import PATTERNS, R, maximum, handoff, command
from process_runtime.authority import operation_name, resource_for, OPCODES
from process_runtime.domain import Snapshot
from process_runtime.contracts import validate

input_overhead = len(Snapshot.of(handoff("")).text.encode()) - len(
    Snapshot.of({"value": ""}).text.encode()
)
bodies = [(name, maximum(pattern)) for name, pattern in PATTERNS]
bodies += [
    ("handoff", maximum(chr(127), handoff)),
    ("handoff-input-max", maximum(chr(127), handoff, size=1_048_576 + input_overhead)),
]
cases = []
for name, body in bodies:
    snapshot = validate(body, "command")
    cases.append(
        {
            "name": name,
            "request": snapshot.text,
            "operation": operation_name(snapshot),
            "resource": resource_for(snapshot),
            "opcode": OPCODES[body["operation"]],
            "max_transport": True,
        }
    )
Path(sys.argv[1]).write_text(
    json.dumps(cases, ensure_ascii=False, separators=(",", ":"))
)
if len(sys.argv) > 2:
    target = Path(sys.argv[2])
    target.mkdir(parents=True, exist_ok=True)
    vectors = [(name, body, True) for name, body in bodies]
    vectors += [
        (name + "-over", maximum(pattern, size=R + 1), False)
        for name, pattern in PATTERNS
    ]
    numbers = command(
        {
            "negative_zero": -0.0,
            "decimal": 1.25,
            "exponent": 1.25e-20,
            "large_exponent": 1e20,
            "large_integer": 2**100,
            "escaped": "\0\n\x7fé🌸",
        }
    )
    vectors.append(("numeric-control", numbers, True))
    manifest = []
    for name, body, accept in vectors:
        raw = Snapshot.of(body).text.encode()
        path = target / (name + ".json")
        path.write_bytes(raw)
        manifest.append(
            {
                "name": name,
                "path": path.name,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "runtime_request_admission_expected": accept,
            }
        )
    (target / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "runtime.request-budget-vectors.v1",
                "scope": "Exact Python canonical request bytes; size+JSON admission only, not handler/authority qualification.",
                "generator_sha256": hashlib.sha256(
                    Path(__file__).read_bytes()
                ).hexdigest(),
                "vectors": manifest,
            },
            indent=2,
        )
        + "\n"
    )
