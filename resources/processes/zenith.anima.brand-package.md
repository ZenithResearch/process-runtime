# Zenith Anima brand package process

This reviewed source defines the first Zenith-owned service offered to Anima clients. Only the explicit `process-json` block below is executable. It does not grant authority or choose an actor.

The process accepts immutable artifacts for the reviewed brief and selected-reference manifest. Research branches can run in parallel. `human-approval` is a manual boundary: the handler must fail the Attempt when the direction is rejected or changes are required. `package-deliverables` must refuse `approved: false`, must commit every generated artifact through Process Runtime before completion, and must return the committed references.

The expert roundtable is a documented review method, not an assertion that a named person participated. Handler prompts, approved personas, source citations and findings belong in `roundtable_record`.

```process-json
{
  "inputs": {
    "organization_name": {
      "kind": "string"
    },
    "reference_manifest": {
      "kind": "artifact"
    },
    "reviewed_brief": {
      "kind": "artifact"
    }
  },
  "process_id": "zenith.anima.brand-package",
  "schema": "process.draft.v1",
  "steps": [
    {
      "bindings": {
        "organization_name": {
          "name": "organization_name",
          "source": "run_input"
        },
        "reference_manifest": {
          "name": "reference_manifest",
          "source": "run_input"
        },
        "reviewed_brief": {
          "name": "reviewed_brief",
          "source": "run_input"
        }
      },
      "capabilities": [
        "brand.intake.qualify"
      ],
      "depends_on": [],
      "inputs": {
        "organization_name": {
          "kind": "string"
        },
        "reference_manifest": {
          "kind": "artifact"
        },
        "reviewed_brief": {
          "kind": "artifact"
        }
      },
      "max_attempts": 2,
      "outputs": {
        "qualified_brief": {
          "kind": "artifact"
        }
      },
      "resources": [
        "brand.workspace"
      ],
      "step_id": "qualify-intake",
      "title": "Validate the reviewed brief and selected references"
    },
    {
      "bindings": {
        "qualified_brief": {
          "name": "qualified_brief",
          "source": "step_output",
          "step_id": "qualify-intake"
        },
        "reference_manifest": {
          "name": "reference_manifest",
          "source": "run_input"
        }
      },
      "capabilities": [
        "brand.research.market"
      ],
      "depends_on": [
        "qualify-intake"
      ],
      "inputs": {
        "qualified_brief": {
          "kind": "artifact"
        },
        "reference_manifest": {
          "kind": "artifact"
        }
      },
      "max_attempts": 2,
      "outputs": {
        "market_research": {
          "kind": "artifact"
        }
      },
      "resources": [
        "brand.workspace",
        "brand.research"
      ],
      "step_id": "research-market",
      "title": "Research audience, category and competitive context"
    },
    {
      "bindings": {
        "qualified_brief": {
          "name": "qualified_brief",
          "source": "step_output",
          "step_id": "qualify-intake"
        },
        "reference_manifest": {
          "name": "reference_manifest",
          "source": "run_input"
        }
      },
      "capabilities": [
        "brand.research.visual"
      ],
      "depends_on": [
        "qualify-intake"
      ],
      "inputs": {
        "qualified_brief": {
          "kind": "artifact"
        },
        "reference_manifest": {
          "kind": "artifact"
        }
      },
      "max_attempts": 2,
      "outputs": {
        "visual_research": {
          "kind": "artifact"
        }
      },
      "resources": [
        "brand.workspace",
        "brand.research"
      ],
      "step_id": "research-visual",
      "title": "Research color, typography and visual references"
    },
    {
      "bindings": {
        "market_research": {
          "name": "market_research",
          "source": "step_output",
          "step_id": "research-market"
        },
        "qualified_brief": {
          "name": "qualified_brief",
          "source": "step_output",
          "step_id": "qualify-intake"
        }
      },
      "capabilities": [
        "brand.strategy.develop"
      ],
      "depends_on": [
        "research-market"
      ],
      "inputs": {
        "market_research": {
          "kind": "artifact"
        },
        "qualified_brief": {
          "kind": "artifact"
        }
      },
      "max_attempts": 2,
      "outputs": {
        "brand_strategy": {
          "kind": "artifact"
        }
      },
      "resources": [
        "brand.workspace"
      ],
      "step_id": "develop-strategy",
      "title": "Develop positioning and brand strategy"
    },
    {
      "bindings": {
        "brand_strategy": {
          "name": "brand_strategy",
          "source": "step_output",
          "step_id": "develop-strategy"
        },
        "reference_manifest": {
          "name": "reference_manifest",
          "source": "run_input"
        },
        "visual_research": {
          "name": "visual_research",
          "source": "step_output",
          "step_id": "research-visual"
        }
      },
      "capabilities": [
        "brand.system.develop"
      ],
      "depends_on": [
        "develop-strategy",
        "research-visual"
      ],
      "inputs": {
        "brand_strategy": {
          "kind": "artifact"
        },
        "reference_manifest": {
          "kind": "artifact"
        },
        "visual_research": {
          "kind": "artifact"
        }
      },
      "max_attempts": 2,
      "outputs": {
        "creative_system": {
          "kind": "artifact"
        }
      },
      "resources": [
        "brand.workspace"
      ],
      "step_id": "develop-system",
      "title": "Develop visual direction, voice and messaging system"
    },
    {
      "bindings": {
        "brand_strategy": {
          "name": "brand_strategy",
          "source": "step_output",
          "step_id": "develop-strategy"
        },
        "creative_system": {
          "name": "creative_system",
          "source": "step_output",
          "step_id": "develop-system"
        },
        "qualified_brief": {
          "name": "qualified_brief",
          "source": "step_output",
          "step_id": "qualify-intake"
        }
      },
      "capabilities": [
        "brand.review.roundtable"
      ],
      "depends_on": [
        "develop-system"
      ],
      "inputs": {
        "brand_strategy": {
          "kind": "artifact"
        },
        "creative_system": {
          "kind": "artifact"
        },
        "qualified_brief": {
          "kind": "artifact"
        }
      },
      "max_attempts": 2,
      "outputs": {
        "reviewed_strategy": {
          "kind": "artifact"
        },
        "reviewed_system": {
          "kind": "artifact"
        },
        "roundtable_record": {
          "kind": "artifact"
        }
      },
      "resources": [
        "brand.workspace"
      ],
      "step_id": "roundtable-review",
      "title": "Review strategy and creative system through the approved expert roundtable"
    },
    {
      "bindings": {
        "reviewed_strategy": {
          "name": "reviewed_strategy",
          "source": "step_output",
          "step_id": "roundtable-review"
        },
        "reviewed_system": {
          "name": "reviewed_system",
          "source": "step_output",
          "step_id": "roundtable-review"
        },
        "roundtable_record": {
          "name": "roundtable_record",
          "source": "step_output",
          "step_id": "roundtable-review"
        }
      },
      "capabilities": [
        "brand.review.human"
      ],
      "depends_on": [
        "roundtable-review"
      ],
      "inputs": {
        "reviewed_strategy": {
          "kind": "artifact"
        },
        "reviewed_system": {
          "kind": "artifact"
        },
        "roundtable_record": {
          "kind": "artifact"
        }
      },
      "max_attempts": 1,
      "outputs": {
        "approval_record": {
          "kind": "artifact"
        },
        "approved": {
          "kind": "boolean"
        }
      },
      "resources": [
        "brand.workspace",
        "brand.human-review"
      ],
      "step_id": "human-approval",
      "title": "Human review and approval of the proposed brand direction"
    },
    {
      "bindings": {
        "approval_record": {
          "name": "approval_record",
          "source": "step_output",
          "step_id": "human-approval"
        },
        "approved": {
          "name": "approved",
          "source": "step_output",
          "step_id": "human-approval"
        },
        "organization_name": {
          "name": "organization_name",
          "source": "run_input"
        },
        "reviewed_strategy": {
          "name": "reviewed_strategy",
          "source": "step_output",
          "step_id": "roundtable-review"
        },
        "reviewed_system": {
          "name": "reviewed_system",
          "source": "step_output",
          "step_id": "roundtable-review"
        },
        "roundtable_record": {
          "name": "roundtable_record",
          "source": "step_output",
          "step_id": "roundtable-review"
        }
      },
      "capabilities": [
        "brand.package.assemble"
      ],
      "depends_on": [
        "human-approval"
      ],
      "inputs": {
        "approval_record": {
          "kind": "artifact"
        },
        "approved": {
          "kind": "boolean"
        },
        "organization_name": {
          "kind": "string"
        },
        "reviewed_strategy": {
          "kind": "artifact"
        },
        "reviewed_system": {
          "kind": "artifact"
        },
        "roundtable_record": {
          "kind": "artifact"
        }
      },
      "max_attempts": 2,
      "outputs": {
        "brand_package": {
          "kind": "artifact"
        },
        "deliverable_manifest": {
          "kind": "artifact"
        },
        "quality_report": {
          "kind": "artifact"
        }
      },
      "resources": [
        "brand.workspace"
      ],
      "step_id": "package-deliverables",
      "title": "Assemble and verify the approved brand package"
    }
  ],
  "title": "Develop and review a brand package"
}
```

## Execution qualification

Publication pins structure; it does not prove the capabilities are installed. A production service remains unavailable until qualified actors can perform every declared capability, the manual reviewer is registered separately, and an end-to-end run returns committed artifacts and canonical receipts.
