#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RESULTS_DIR="${SLOTGUARD_RESULTS_DIR:-experiments/results}"
DATA_DIR="${SLOTGUARD_DATA_DIR:-experiments/data}"
TAC_ROOT="${SLOTGUARD_TAC_ROOT:-../TheAgentCompany}"
TAC_MODE="${SLOTGUARD_TAC_MODE:-hybrid}"
VARIANTS="${SLOTGUARD_TAC_VARIANTS:-4}"
SEED="${SLOTGUARD_TAC_SEED:-60759907223582021}"
SPEC_FILE="${SLOTGUARD_TAC_MODEL_SPEC_FILE:-../model_generalization.md}"
TIMEOUT_MS="${SLOTGUARD_MODEL_GEN_TIMEOUT_MS:-180000}"
MAX_MODELS="${SLOTGUARD_TAC_MAX_MODELS:-4}"

if [[ -z "${SLOTGUARD_MODEL_API_KEY:-}" ]]; then
  echo "SLOTGUARD_MODEL_API_KEY must be set before running TAC-lite multi-model comparison." >&2
  exit 2
fi

if [[ ! -d "$TAC_ROOT" ]]; then
  echo "TAC root not found: $TAC_ROOT" >&2
  echo "Clone TheAgentCompany next to SlotGuard or set SLOTGUARD_TAC_ROOT." >&2
  exit 2
fi

if [[ ! -f "$SPEC_FILE" ]]; then
  echo "Model spec file not found: $SPEC_FILE" >&2
  exit 2
fi

mkdir -p "$RESULTS_DIR" "$DATA_DIR"

cargo run --release -p slotguard-experiments -- tac-lite-generate \
  --tac-root "$TAC_ROOT" \
  --mode "$TAC_MODE" \
  --out "$DATA_DIR/tac_lite.json" \
  --variants-per-task "$VARIANTS" \
  --seed "$SEED"

cargo run --release -p slotguard-experiments -- tac-lite-model-gen \
  --dataset "$DATA_DIR/tac_lite.json" \
  --spec-file "$SPEC_FILE" \
  --out "$RESULTS_DIR/tac_lite_model_gen.json" \
  --max-models "$MAX_MODELS" \
  --timeout-ms "$TIMEOUT_MS"

cargo run --release -p slotguard-experiments -- report --results-dir "$RESULTS_DIR" --out "$RESULTS_DIR/REPORT.md"
