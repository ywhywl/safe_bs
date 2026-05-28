#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INPUT_DIR="${1:?imported recon dir required}"
RUN_PREFIX="${RUN_PREFIX:-$(date -u +"%Y%m%dT%H%M%SZ")}"
TARGETS="${TARGETS:-${2:-}}"
SCOPE="${SCOPE:-authorized testing only}"
WINDOW="${WINDOW:-}"
NETWORK_PATH="${NETWORK_PATH:-external}"
WORK_DIR="${WORK_DIR:-/private/tmp/task1_batch_${RUN_PREFIX}}"

export PYTHONPATH="${PROJECT_ROOT}/scripts/common"

python3 "${PROJECT_ROOT}/scripts/task1/run_batch_import.py" \
  --project-root "${PROJECT_ROOT}" \
  --input-dir "${INPUT_DIR}" \
  --run-prefix "${RUN_PREFIX}" \
  --targets "${TARGETS}" \
  --scope "${SCOPE}" \
  --window "${WINDOW}" \
  --network-path "${NETWORK_PATH}" \
  --work-dir "${WORK_DIR}"
