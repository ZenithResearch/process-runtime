"""Regenerate the public v1 contract; do not edit generated JSON by hand."""
from pathlib import Path
from process_runtime.contracts import write_schema
write_schema(Path(__file__).resolve().parents[1] / "contracts" / "runtime-v1.schema.json")
