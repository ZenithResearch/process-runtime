# Process authoring, compilation and publication

Tasks: `process-schema-and-authoring-boundary`, `process-compiler-validation`,
`process-publication-hash-fixtures`.

The source contract remains `process.draft.v1` in `contracts.py` and its generated
JSON Schema. `authoring.import_document` accepts at most 1 MiB of UTF-8 JSON,
Markdown or plain text. JSON uploads contain the explicit draft object. Markdown
and text contain exactly one standalone fenced `process-json` block. Surrounding
prose is documentation and never creates steps, permissions, dependencies or data
bindings. Nested example fences are ignored. Missing, duplicate, unclosed,
malformed or semantically invalid process blocks return an `AuthoringResult` with
no draft and explicit uncertainty. Unsupported formats fail closed; PDF, Word,
HTML and URLs are not implicitly converted or fetched.

Provenance records source ID, declared media type, SHA-256 of exact uploaded bytes,
parser version and uncertainties. The authoring result retains snapshots by value;
its `definition(revision=...)` method requires an accepted result. No parser invokes
a model or guesses at ambiguous prose. `render_markdown` creates a human-readable
document with the exact authoritative JSON block. Parser diagnostics do not echo
arbitrary source content. An operator must supply corrected explicit structure to
resolve uncertainty; clearing a warning does not infer the missing graph.

`compiler.compile_draft` validates the closed schema plus semantic invariants:

- Step IDs are unique; dependencies exist; self edges and cycles are rejected.
- Every input has exactly one binding. Source ports exist. Output references must
  name an explicitly declared dependency ancestor, including transitive ancestors.
  Referencing an output never silently adds an edge or changes scheduling order.
- Run inputs, output bindings and literals match recursive types. All top-level
  ports are required. Object types are closed and carry explicit required names;
  undeclared required properties fail compilation. Integer output may feed number
  input; the reverse is rejected. Booleans do not count as integers. Object
  assignment must guarantee target required fields and cannot emit unknown fields.
- Capabilities and resources are retained exactly as declared, sorted for hashing.
  They are eligibility requirements, not authentication grants. Artifact values
  are immutable content references; type validation alone does not prove their
  availability or byte integrity.

The compiled snapshot has schema `process.compiled.v1` and compiler version
`process-runtime.compiler.v1`. It retains process identity, optional title, inputs
and all normalized step fields, plus sorted roots, deterministic topological order
and sorted ancestor sets. Steps and set-like lists are sorted; literal arrays keep
their semantic order. SHA-256 covers the existing canonical UTF-8 Snapshot bytes.
Source whitespace, map insertion order and unordered step declarations do not
change the compiled hash. Changes to titles, types, dependencies, bindings,
capabilities, resources or retry policy do. Provenance and publication timestamps
remain separate from executable compilation, so identical explicit processes can
be compiled reproducibly from different source documents.

`compile_definition` returns a `CompiledSource` retaining the exact immutable
definition, revision, source draft, provenance and compiled value. Process identity
must match the draft. `publish` builds a `ProcessVersion` for a supplied exact
revision, version ID, ordinal and timestamp; it recompiles that definition and
rejects unresolved parser uncertainty. It does not read a clock, choose IDs, change
a draft or persist anything. A later draft revision cannot mutate that version or
an existing run pin.

The application atomically compares the stored draft revision and inserts the
immutable version, retained source/provenance, publication event and idempotent
result through `RuntimeStore`. It enforces unique version IDs and ordinals and
updates the active-version pointer. These transaction guarantees are covered by
application and SQLite tests; the pure builder has no persistence authority.

`validate_values(values, ports)` is the common typed boundary for run input and
step output objects; all port names must match exactly. The compiler limits source
size, JSON structure and nested type depth. It has no runtime, service-management,
Wallet, database, HTTP or event-bus dependency. The golden personal-review fixture
demonstrates an ordinary non-service ProcessRun, transitive bindings and an artifact
output. The full personal-review and development SOP resources are also executed by
`tests/test_shadow.py`; `process-resources-and-shadow-v1.md` describes their
fixture boundaries and production limitations.

Verification uses `tests/test_compiler.py` and the retained draft/compiled golden
fixtures in `tests/fixtures/process-publication`. The tests check rejection paths,
directional recursive typing, deterministic normalization, hash binding and
immutable revision/version pinning. This is a new compiler output contract; no
legacy Hub Case snapshot is reinterpreted or migrated. Future incompatible compiler
semantics require a new compiler/schema version and consumer qualification.
