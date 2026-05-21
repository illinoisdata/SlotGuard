#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RESULTS_DIR="${SLOTGUARD_RESULTS_DIR:-experiments/results}"
DATA_DIR="${SLOTGUARD_DATA_DIR:-experiments/data}"
TAC_ROOT="${SLOTGUARD_TAC_ROOT:-../TheAgentCompany}"
TAC_MODE="${SLOTGUARD_TAC_MODE:-hybrid}"
LOCAL_ENDPOINT="${SLOTGUARD_LOCAL_ENDPOINT:-http://127.0.0.1:11434/v1/chat/completions}"
LOCAL_MODEL="${SLOTGUARD_LOCAL_MODEL:-qwen2.5-coder:1.5b}"
LOCAL_AUTH_STYLE="${SLOTGUARD_LOCAL_AUTH_STYLE:-none}"
LOCAL_API_KEY_ENV="${SLOTGUARD_LOCAL_API_KEY_ENV:-SLOTGUARD_MODEL_API_KEY}"
TIMEOUT_MS="${SLOTGUARD_LOCAL_TIMEOUT_MS:-60000}"
VARIANTS="${SLOTGUARD_TAC_VARIANTS:-4}"
SEED="${SLOTGUARD_TAC_SEED:-60759907223582021}"

if [[ ! -d "$TAC_ROOT" ]]; then
  echo "TAC root not found: $TAC_ROOT" >&2
  echo "Clone TheAgentCompany next to SlotGuard or set SLOTGUARD_TAC_ROOT." >&2
  exit 2
fi

mkdir -p "$RESULTS_DIR" "$DATA_DIR"

cargo run --release -p slotguard-experiments -- tac-lite-generate \
  --tac-root "$TAC_ROOT" \
  --mode "$TAC_MODE" \
  --out "$DATA_DIR/tac_lite.json" \
  --variants-per-task "$VARIANTS" \
  --seed "$SEED"

cargo run --release -p slotguard-experiments -- tac-lite-exp4 \
  --dataset "$DATA_DIR/tac_lite.json" \
  --endpoint "$LOCAL_ENDPOINT" \
  --model "$LOCAL_MODEL" \
  --auth-style "$LOCAL_AUTH_STYLE" \
  --api-key-env "$LOCAL_API_KEY_ENV" \
  --timeout-ms "$TIMEOUT_MS" \
  --out "$RESULTS_DIR/tac_lite.json"

cargo run --release -p slotguard-experiments -- report --results-dir "$RESULTS_DIR" --out "$RESULTS_DIR/REPORT.md"
