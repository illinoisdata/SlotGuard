# Reproducing SlotGuard Experiments

This directory contains the active SlotGuard implementation and the scripts
used to reproduce the current paper results.

## Prerequisites

- Rust toolchain with `cargo`
- `python3` for `experiments/scripts/criterion_summary.py`
- Optional for local-model experiments:
  - Ollama, `vllm`, or another OpenAI-compatible local endpoint
- Optional for model generalization:
  - valid Azure/OpenAI-compatible specs in
    [../model_generalization.md](../model_generalization.md)
  - `SLOTGUARD_MODEL_API_KEY` set in the environment for remote models

All commands below should be run from [SlotGuard](./).

## 1. One-Command Paper Flow

```bash
cp .env.example .env
set -a
source .env
set +a

./scripts/repro_paper.sh
```

`repro_paper.sh` is the orchestration entry point for open-source
reproduction. By default it runs:

- `verify_workspace.sh`
- `repro_core.sh`

Optional stages are gated by environment flags so that users do not need a
local or remote model endpoint just to reproduce the deterministic results:

- `SLOTGUARD_RUN_LOCAL=1` — local `exp4` and `exp6`
- `SLOTGUARD_RUN_MODEL_GEN=1` — remote 200-task multi-model probe
- `SLOTGUARD_RUN_TAC_LITE=1` — TAC-lite single-model replay
- `SLOTGUARD_RUN_TAC_LITE_MODEL_GEN=1` — TAC-lite four-model replay

## 2. Verify The Workspace

```bash
./scripts/verify_workspace.sh
```

This runs:

- `bash -n scripts/*.sh`
- `cargo fmt --all --check`
- `cargo test`

## 3. Reproduce The Deterministic Core Results

```bash
./scripts/repro_core.sh
```

This regenerates:

- `experiments/data/corpus.json`
- `experiments/data/credentials.json`
- `experiments/results/placement.json`
- `experiments/results/exp1.json`
- `experiments/results/exp2.json`
- `experiments/results/exp3.json`
- `experiments/results/exp5.json`
- `experiments/results/credentials.json`
- `experiments/results/format_validity.json`
- `experiments/results/REPORT.md`

It also runs the Criterion microbench for `slotguard-core` and converts the
summary into `experiments/results/exp3.json`.

## 4. Reproduce Local-Model Experiments

```bash
./scripts/repro_local_model.sh
```

Default environment:

- `SLOTGUARD_LOCAL_ENDPOINT=http://127.0.0.1:11434/v1/chat/completions`
- `SLOTGUARD_LOCAL_MODEL=qwen2.5-coder:1.5b`
- `SLOTGUARD_LOCAL_TIMEOUT_MS=60000`

This regenerates:

- `experiments/results/exp4.json`
- `experiments/results/exp6.json`
- `experiments/results/REPORT.md`

Example:

```bash
SLOTGUARD_LOCAL_MODEL=gemma3:1b ./scripts/repro_local_model.sh
```

## 5. Reproduce TAC-lite Real-Task Replay

```bash
./scripts/repro_tac_lite.sh
```

Default environment:

- `SLOTGUARD_TAC_ROOT=../TheAgentCompany`
- `SLOTGUARD_TAC_MODE=hybrid`
- `SLOTGUARD_TAC_VARIANTS=4`
- `SLOTGUARD_TAC_SEED=60759907223582021`
- `SLOTGUARD_LOCAL_ENDPOINT=http://127.0.0.1:11434/v1/chat/completions`
- `SLOTGUARD_LOCAL_MODEL=qwen2.5-coder:1.5b`
- `SLOTGUARD_LOCAL_AUTH_STYLE=none`
- `SLOTGUARD_LOCAL_API_KEY_ENV=SLOTGUARD_MODEL_API_KEY`
- `SLOTGUARD_LOCAL_TIMEOUT_MS=60000`

This regenerates:

- `experiments/data/tac_lite.json`
- `experiments/results/tac_lite.json`
- `experiments/results/REPORT.md`

`tac_lite` is a lightweight replay benchmark derived from
`TheAgentCompany/workspaces/tasks/*/{task.md,evaluator.py}`. It preserves
the real task wording and target file handles, but it does **not** attempt to
recreate TAC's full Dockerized online environment.

Current default `hybrid` mode combines:

- a curated set of repo-centric TAC tasks
- all evaluator-grounded local handles extracted from `with open(...)`,
  `cwd=...`, and `destination=...` patterns

With the current TAC checkout this yields 160 replay tasks
(33 task families, 40 grounded handles, 4 workspace variants each).

For remote OpenAI-compatible endpoints such as Azure-hosted deployments, set:

```bash
export SLOTGUARD_MODEL_API_KEY=...
SLOTGUARD_LOCAL_ENDPOINT=https://<resource>.services.ai.azure.com/openai/v1/chat/completions \
SLOTGUARD_LOCAL_MODEL=gpt-5.4 \
SLOTGUARD_LOCAL_AUTH_STYLE=bearer \
./scripts/repro_tac_lite.sh
```

## 6. Reproduce TAC-lite Multi-Model Comparison

```bash
./scripts/repro_tac_lite_model_gen.sh
```

Default environment:

- `SLOTGUARD_TAC_ROOT=../TheAgentCompany`
- `SLOTGUARD_TAC_MODE=hybrid`
- `SLOTGUARD_TAC_VARIANTS=4`
- `SLOTGUARD_TAC_MODEL_SPEC_FILE=../model_generalization.md`
- `SLOTGUARD_TAC_MAX_MODELS=4`
- `SLOTGUARD_MODEL_GEN_TIMEOUT_MS=180000`
- `SLOTGUARD_MODEL_API_KEY=<your-api-key>`

This regenerates:

- `experiments/data/tac_lite.json`
- `experiments/results/tac_lite_model_gen.json`
- `experiments/results/REPORT.md`

This script shares the same public model-spec template as
`repro_model_gen.sh`; there is no TAC-specific secret config file in the
open repository.

## 7. Reproduce Multi-Model Generalization

```bash
./scripts/repro_model_gen.sh
```

Default environment:

- `SLOTGUARD_MODEL_SPEC_FILE=../model_generalization.md`
- `SLOTGUARD_MODEL_GEN_TASKS=200`
- `SLOTGUARD_MODEL_GEN_TIMEOUT_MS=180000`
- `SLOTGUARD_MODEL_API_KEY=<your-api-key>`

This regenerates:

- `experiments/results/model_gen.json`
- `experiments/results/REPORT.md`

## Notes

- The active code path is the non-MCP transcript-boundary implementation.
- External baseline repositories under `../VibeGuard` and
  `../opencode-vibeguard` are left untouched as references.
- `../model_generalization.md` is the canonical public template for the four
  remote-model probes. Fill in your own deployment endpoints and set
  `SLOTGUARD_MODEL_API_KEY` in the environment.
- Raw generated corpora and JSON experiment artifacts are intentionally
  ignored in the public repository because they contain synthetic
  secret-shaped strings that can trigger secret scanners. Regenerate them
  locally with the scripts above.
- `REPORT.md` is derived from the JSON artifacts, so rerun `report` after any
  partial experiment sequence if you want the markdown summary refreshed.
