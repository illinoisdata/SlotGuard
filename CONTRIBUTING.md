# Contributing

## Development flow

1. Work inside [SlotGuard](./).
2. Run `./scripts/verify_workspace.sh` before opening a PR.
3. If you change experiments, regenerate only the artifacts you need
   locally; do not commit generated `experiments/data/*.json` or
   `experiments/results/*.json` files.
4. Refresh `experiments/results/REPORT.md` if your change affects reported
   numbers or benchmark behavior.

## Security and privacy hygiene

- Never commit real API keys, tokens, passwords, or private endpoints.
- Use environment variables such as `SLOTGUARD_MODEL_API_KEY` for remote
  model access.
- Synthetic benchmark data intentionally resembles secrets at runtime, so it
  is generated locally and ignored in the public repository.

## Useful commands

```bash
./scripts/verify_workspace.sh
./scripts/repro_core.sh
./scripts/repro_local_model.sh
./scripts/repro_model_gen.sh
```
