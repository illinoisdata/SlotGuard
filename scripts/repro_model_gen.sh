#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RESULTS_DIR="${SLOTGUARD_RESULTS_DIR:-experiments/results}"
SPEC_FILE="${SLOTGUARD_MODEL_SPEC_FILE:-../model_generalization.md}"
TASKS="${SLOTGUARD_MODEL_GEN_TASKS:-200}"
TIMEOUT_MS="${SLOTGUARD_MODEL_GEN_TIMEOUT_MS:-180000}"

if [[ -z "${SLOTGUARD_MODEL_API_KEY:-}" ]]; then
  echo "SLOTGUARD_MODEL_API_KEY must be set before running remote model generalization." >&2
  exit 2
fi

if [[ ! -f "$SPEC_FILE" ]]; then
  echo "Model spec file not found: $SPEC_FILE" >&2
  exit 2
fi

mkdir -p "$RESULTS_DIR"

cargo run --release -p slotguard-experiments -- model-gen \
  --spec-file "$SPEC_FILE" \
  --out "$RESULTS_DIR/model_gen.json" \
  --max-tasks "$TASKS" \
  --timeout-ms "$TIMEOUT_MS"

cargo run --release -p slotguard-experiments -- report --results-dir "$RESULTS_DIR" --out "$RESULTS_DIR/REPORT.md"
