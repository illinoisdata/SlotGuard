#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_VERIFY="${SLOTGUARD_RUN_VERIFY:-1}"
RUN_CORE="${SLOTGUARD_RUN_CORE:-1}"
RUN_LOCAL="${SLOTGUARD_RUN_LOCAL:-0}"
RUN_MODEL_GEN="${SLOTGUARD_RUN_MODEL_GEN:-0}"
RUN_TAC_LITE="${SLOTGUARD_RUN_TAC_LITE:-0}"
RUN_TAC_LITE_MODEL_GEN="${SLOTGUARD_RUN_TAC_LITE_MODEL_GEN:-0}"

run_step() {
  local label="$1"
  shift
  echo
  echo "==> $label"
  "$@"
}

echo "SlotGuard paper reproduction"
echo "  verify=$RUN_VERIFY core=$RUN_CORE local=$RUN_LOCAL model_gen=$RUN_MODEL_GEN tac_lite=$RUN_TAC_LITE tac_lite_model_gen=$RUN_TAC_LITE_MODEL_GEN"

if [[ "$RUN_VERIFY" == "1" ]]; then
  run_step "Verify workspace" ./scripts/verify_workspace.sh
fi

if [[ "$RUN_CORE" == "1" ]]; then
  run_step "Deterministic core experiments" ./scripts/repro_core.sh
fi

if [[ "$RUN_LOCAL" == "1" ]]; then
  run_step "Local-model experiments" ./scripts/repro_local_model.sh
fi

if [[ "$RUN_MODEL_GEN" == "1" ]]; then
  run_step "Remote multi-model generalization" ./scripts/repro_model_gen.sh
fi

if [[ "$RUN_TAC_LITE" == "1" ]]; then
  run_step "TAC-lite replay benchmark" ./scripts/repro_tac_lite.sh
fi

if [[ "$RUN_TAC_LITE_MODEL_GEN" == "1" ]]; then
  run_step "TAC-lite multi-model comparison" ./scripts/repro_tac_lite_model_gen.sh
fi

echo
echo "Done. Refresh summary at experiments/results/REPORT.md"
