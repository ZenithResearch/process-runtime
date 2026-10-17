# Process personal-review

Only the explicit process-json block defines executable structure. Surrounding prose is documentation.

```process-json
{
  "inputs": {
    "notes": {
      "kind": "string"
    }
  },
  "process_id": "personal-review",
  "schema": "process.draft.v1",
  "steps": [
    {
      "bindings": {
        "notes": {
          "name": "notes",
          "source": "run_input"
        }
      },
      "capabilities": [
        "notes.read",
        "review.prepare"
      ],
      "depends_on": [],
      "inputs": {
        "notes": {
          "kind": "string"
        }
      },
      "max_attempts": 1,
      "outputs": {
        "brief": {
          "kind": "string"
        }
      },
      "resources": [
        "personal.workspace",
        "notes.source"
      ],
      "step_id": "capture",
      "title": "Capture observations"
    },
    {
      "bindings": {
        "brief": {
          "name": "brief",
          "source": "step_output",
          "step_id": "capture"
        },
        "maximum": {
          "source": "literal",
          "value": 3
        }
      },
      "capabilities": [
        "review.decide"
      ],
      "depends_on": [
        "capture"
      ],
      "inputs": {
        "brief": {
          "kind": "string"
        },
        "maximum": {
          "kind": "integer"
        }
      },
      "max_attempts": 1,
      "outputs": {
        "decision": {
          "kind": "object",
          "properties": {
            "approved": {
              "kind": "boolean"
            },
            "reasons": {
              "items": {
                "kind": "string"
              },
              "kind": "array"
            }
          },
          "required": [
            "approved",
            "reasons"
          ]
        }
      },
      "resources": [
        "personal.workspace"
      ],
      "step_id": "review",
      "title": "Review observations"
    },
    {
      "bindings": {
        "decision": {
          "name": "decision",
          "source": "step_output",
          "step_id": "review"
        },
        "original": {
          "name": "brief",
          "source": "step_output",
          "step_id": "capture"
        }
      },
      "capabilities": [
        "review.record"
      ],
      "depends_on": [
        "review"
      ],
      "inputs": {
        "decision": {
          "kind": "object",
          "properties": {
            "approved": {
              "kind": "boolean"
            },
            "reasons": {
              "items": {
                "kind": "string"
              },
              "kind": "array"
            }
          },
          "required": [
            "approved",
            "reasons"
          ]
        },
        "original": {
          "kind": "string"
        }
      },
      "max_attempts": 1,
      "outputs": {
        "record": {
          "kind": "artifact"
        }
      },
      "resources": [
        "personal.workspace",
        "review.store"
      ],
      "step_id": "record",
      "title": "Record the review"
    }
  ],
  "title": "Personal review"
}
```
