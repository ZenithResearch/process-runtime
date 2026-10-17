"""Bounded, explicit authoring import without prose-to-process inference."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re

from .compiler import MAX_DOCUMENT_BYTES, compile_draft
from .domain import DomainError, ProcessDefinition, Snapshot, identifier, sha256

PARSER_VERSION = "process-runtime.authoring.v1"
SUPPORTED_MEDIA_TYPES = frozenset(("application/json", "text/markdown", "text/plain"))


@dataclass(frozen=True)
class AuthoringResult:
    draft: Snapshot | None
    provenance: Snapshot

    @property
    def uncertainties(self) -> tuple[str, ...]:
        return tuple(self.provenance.value["uncertainties"])

    @property
    def accepted(self) -> bool:
        return self.draft is not None and not self.uncertainties

    def definition(self, *, revision: int) -> ProcessDefinition:
        if not self.accepted:
            raise DomainError("invalid_dag", "Explicit valid process structure is required")
        return ProcessDefinition(self.draft.value["process_id"], revision, self.draft, self.provenance)


def _pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON key")
        result[name] = value
    return result


def _constant(_value):
    raise ValueError("nonfinite JSON value")


def import_document(content: bytes, *, source_id: str, media_type: str) -> AuthoringResult:
    """Accept JSON, or exactly one standalone ```process-json Markdown block.

    Text outside the explicit block is non-executable documentation. Missing,
    duplicate, malformed or unclosed blocks surface uncertainty. No files are
    opened, URLs fetched, code evaluated, or ambiguous prose translated.
    """
    identifier(source_id)
    if type(content) is not bytes or len(content) > MAX_DOCUMENT_BYTES:
        raise DomainError("malformed_request", "Document must be bounded bytes")
    if media_type not in SUPPORTED_MEDIA_TYPES:
        raise DomainError("unsupported_contract", "Supported uploads are JSON, Markdown and UTF-8 text")
    provenance = {"source_id": source_id, "media_type": media_type, "content_hash": sha256(content),
                  "parser": PARSER_VERSION, "uncertainties": []}

    def uncertain(message: str) -> AuthoringResult:
        return AuthoringResult(None, Snapshot.of({**provenance, "uncertainties": [message]}))

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return uncertain("Document is not valid UTF-8 text")
    if media_type == "application/json":
        source = text
    else:
        lines = text.splitlines()
        blocks = []
        current = None
        # A process block nested inside another fenced example is not executable.
        other_fence = None
        for line in lines:
            if current is not None:
                if re.fullmatch(r" {0,3}```\s*", line):
                    blocks.append("\n".join(current))
                    current = None
                else:
                    current.append(line)
                continue
            match = re.fullmatch(r" {0,3}(`{3,}|~{3,})(.*)", line)
            if not match:
                continue
            fence, suffix = match.groups()
            if other_fence is not None:
                if fence[0] == other_fence[0] and len(fence) >= len(other_fence) and not suffix.strip():
                    other_fence = None
                continue
            if fence == "```" and suffix.strip() == "process-json":
                current = []
            else:
                other_fence = fence
        if current is not None:
            return uncertain("Explicit process-json block is not closed")
        if len(blocks) != 1:
            return uncertain("Provide exactly one explicit process-json block; prose is not interpreted")
        source = blocks[0]
    try:
        raw = json.loads(source, object_pairs_hook=_pairs, parse_constant=_constant)
        compile_draft(raw)
        draft = Snapshot.of(raw)
    except (DomainError, ValueError, UnicodeError, RecursionError):
        return uncertain("Explicit process structure is invalid; resolve schema, DAG or type errors")
    return AuthoringResult(draft, Snapshot.of(provenance))


def render_markdown(draft: Snapshot | dict) -> str:
    """Render a reviewable authoring document whose JSON is the sole authority."""
    raw = draft.value if isinstance(draft, Snapshot) else draft
    compiled = compile_draft(raw)
    body = json.dumps(raw, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
    return (f"# Process {compiled.process_id}\n\n"
            "Only the explicit process-json block defines executable structure. "
            "Surrounding prose is documentation.\n\n"
            f"```process-json\n{body}\n```\n")
