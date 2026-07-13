#!/usr/bin/env bash
# Endpoint & Auth Mapper — local pre-commit gate.
#
# Blocks a commit that introduces a high-confidence EXPOSED endpoint. Findings
# already recorded in .authmap-baseline.json are ignored, so legacy debt does
# not block day-to-day work.
#
# Install (one of):
#   ln -s ../../ci/pre-commit-hook.sh .git/hooks/pre-commit
#   # or add to .pre-commit-config.yaml as a local 'system' hook.
set -euo pipefail

PROJECT_ROOT="$(git rev-parse --show-toplevel)"

# Prefer an installed console script; fall back to module invocation.
if command -v authmap >/dev/null 2>&1; then
  RUN=(authmap)
else
  RUN=(python -m authmapper)
fi

echo "[auth-audit] scanning for newly exposed endpoints..."
"${RUN[@]}" \
  --project "${PROJECT_ROOT}" \
  --fail-on EXPOSED \
  --min-confidence high \
  --baseline "${PROJECT_ROOT}/.authmap-baseline.json" \
  --quiet

echo "[auth-audit] no new exposed endpoints. proceeding."
