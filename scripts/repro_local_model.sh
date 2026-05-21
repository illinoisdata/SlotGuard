#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RESULTS_DIR="${SLOTGUARD_RESULTS_DIR:-experiments/results}"
LOCAL_ENDPOINT="${SLOTGUARD_LOCAL_ENDPOINT:-http://127.0.0.1:11434/v1/chat/completions}"
LOCAL_MODEL="${SLOTGUARD_LOCAL_MODEL:-qwen2.5-coder:1.5b}"
TIMEOUT_MS="${SLOTGUARD_LOCAL_TIMEOUT_MS:-60000}"

mkdir -p "$RESULTS_DIR"

cargo run --release -p slotguard-experiments -- exp4 \
  --endpoint "$LOCAL_ENDPOINT" \
  --model "$LOCAL_MODEL" \
  --timeout-ms "$TIMEOUT_MS" \
  --out "$RESULTS_DIR/exp4.json"

cargo run --release -p slotguard-experiments -- exp6 \
  --endpoint "$LOCAL_ENDPOINT" \
  --model "$LOCAL_MODEL" \
  --timeout-ms "$TIMEOUT_MS" \
  --out "$RESULTS_DIR/exp6.json"

cargo run --release -p slotguard-experiments -- report --results-dir "$RESULTS_DIR" --out "$RESULTS_DIR/REPORT.md"
