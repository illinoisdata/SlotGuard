#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RESULTS_DIR="${SLOTGUARD_RESULTS_DIR:-experiments/results}"
DATA_DIR="${SLOTGUARD_DATA_DIR:-experiments/data}"

mkdir -p "$RESULTS_DIR" "$DATA_DIR"

cargo run --release -p slotguard-experiments -- generate --out "$DATA_DIR/corpus.json"
cargo run --release -p slotguard-experiments -- placement --out "$RESULTS_DIR/placement.json"
cargo run --release -p slotguard-experiments -- exp1 --corpus "$DATA_DIR/corpus.json" --out "$RESULTS_DIR/exp1.json"
cargo run --release -p slotguard-experiments -- exp2 --corpus "$DATA_DIR/corpus.json" --out "$RESULTS_DIR/exp2.json"
cargo run --release -p slotguard-experiments -- exp5 --out "$RESULTS_DIR/exp5.json"
cargo run --release -p slotguard-experiments -- generate-credentials --out "$DATA_DIR/credentials.json"
cargo run --release -p slotguard-experiments -- credentials --corpus "$DATA_DIR/credentials.json" --out "$RESULTS_DIR/credentials.json"
cargo run --release -p slotguard-experiments -- format-validity --out "$RESULTS_DIR/format_validity.json"

cargo bench -p slotguard-core
python3 experiments/scripts/criterion_summary.py

cargo run --release -p slotguard-experiments -- report --results-dir "$RESULTS_DIR" --out "$RESULTS_DIR/REPORT.md"
