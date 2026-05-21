# SlotGuard

Active Rust implementation of SlotGuard: a local transcript boundary for
coding agents. SlotGuard rewrites provider-bound transcript state before it
leaves the trusted runtime, removing raw structural bindings and credentials
while preserving the path-shaped and credential-shaped cues that upstream
models still need for workflow reasoning.

## Workspace Layout

- `crates/slotguard-core` — core abstraction, rebinding, credential
  sanitization, format-preserving synthetic substitution (FPS), and the
  session-scoped semantic entity graph (SEG)
- `crates/slotguard-cli` — local inspection and demo commands
- `crates/slotguard-experiments` — the benchmark harness used for the paper
- `experiments/data` — generated corpora
- `experiments/results` — JSON outputs and the rendered `REPORT.md`
- `scripts` — reproducibility and verification helpers

The old MCP server path has been removed. The current codebase follows the
non-MCP, `open_vibeguard`-style transcript-boundary design used by the
paper experiments.

## Quick Start

```bash
cd SlotGuard

cargo run -p slotguard-cli -- test-abstract /workspace/proj_guard/VibeGuard/README.md \
  --workspace-root /workspace/proj_guard

cargo run -p slotguard-cli -- demo-path /workspace/proj_guard/VibeGuard/README.md \
  --workspace-root /workspace/proj_guard

cargo run -p slotguard-cli -- semantic-detect layoff_plan_for_bob_2026.pdf \
  --kind filename \
  --config ./config.example.toml
```

## Reproducibility

The recommended entry points are:

- `scripts/verify_workspace.sh` — format and test the workspace
- `scripts/repro_paper.sh` — orchestrate the full paper reproduction flow
  from environment flags
- `scripts/repro_core.sh` — run the deterministic paper experiments
  (`placement`, `exp1`, `exp2`, `exp5`, `credentials`, `format-validity`,
  criterion summary, and `REPORT.md`)
- `scripts/repro_local_model.sh` — run local-model experiments `exp4` and
  `exp6`
- `scripts/repro_tac_lite.sh` — generate and run the TAC-derived lightweight
  real-task replay benchmark
- `scripts/repro_tac_lite_model_gen.sh` — run the TAC-lite benchmark across
  four remote models
- `scripts/repro_model_gen.sh` — run the 200-task multi-model
  generalization probe from `../model_generalization.md`

See [REPRO.md](./REPRO.md) for prerequisites, environment variables, and the
expected output files.

Before running the remote model-generalization probes, set
`SLOTGUARD_MODEL_API_KEY` and fill in your own deployment endpoints in the
shared spec template
[`../model_generalization.md`](../model_generalization.md). Both
`repro_model_gen.sh` and `repro_tac_lite_model_gen.sh` read from that file.

If you want one command that mirrors the paper structure, start from:

```bash
cp .env.example .env
set -a
source .env
set +a

./scripts/repro_paper.sh
```

By default this runs only the deterministic experiments. Turn on
`SLOTGUARD_RUN_LOCAL=1`, `SLOTGUARD_RUN_MODEL_GEN=1`,
`SLOTGUARD_RUN_TAC_LITE=1`, and/or `SLOTGUARD_RUN_TAC_LITE_MODEL_GEN=1`
when the corresponding local or remote model endpoints are available.

## TAC-lite Benchmark

SlotGuard also includes a lightweight benchmark derived from
[`TheAgentCompany`](../TheAgentCompany) task descriptions. The `tac_lite`
pipeline extracts a curated subset of repo-centric tasks from TAC's `task.md`
and `evaluator.py` files, plus evaluator-grounded local handles discovered
from explicit `with open(...)`, `cwd=...`, and `destination=...` references.
It instantiates them under local user workspace roots and reuses the
SlotGuard workflow probe to compare raw, generic redaction,
VibeGuard-style placeholders, and the full SlotGuard rewrite.

This benchmark is intentionally lighter than TAC's original setup:

- it reuses real task wording and target handles
- it does not require Dockerized GitLab / RocketChat / ownCloud services
- it should be described as `TAC-derived replay`, not as the full TAC online benchmark

`repro_tac_lite.sh` supports both local unauthenticated endpoints and remote
OpenAI-compatible deployments. For remote endpoints, set
`SLOTGUARD_LOCAL_AUTH_STYLE=bearer` or `api-key-header` and point
`SLOTGUARD_LOCAL_API_KEY_ENV` at the environment variable containing your key.

## Local Semantic Endpoint

SlotGuard can optionally call a local HTTP LLM endpoint for advisory slot
proposals.

- `openai_chat` — OpenAI-compatible local servers such as `vllm`,
  Ollama (`/v1/chat/completions`), `llama.cpp`, or LM Studio
- `anthropic_messages` — Anthropic-style JSON message endpoints

The model only proposes spans and slot types. Runtime verification checks
that the proposed span appears verbatim in the local input before it is
turned into a placeholder.

Example local setup with Ollama:

```bash
ollama pull qwen2.5-coder:1.5b
ollama serve
```

Then enable the semantic layer in `config.example.toml` or pass equivalent
CLI flags.

## Session State

A SlotGuard session pins a per-session HMAC key and an append-only slot
ledger under `~/.slotguard/sessions/<id>/`:

- `session_key` — 32 random bytes, mode `0600`
- `index.json` — current slot-table snapshot
- `slots.jsonl` — append-only slot creation log

Set `SLOTGUARD_HOME` to override the base directory for tests or containers.
Different sessions produce different handles for the same raw value, so
handles are unlinkable across runs.
