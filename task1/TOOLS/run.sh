#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_ID="${RUN_ID:-$(date -u +"%Y%m%dT%H%M%SZ")}"
RUN_DIR="${TOOLS_DIR}/runs/${RUN_ID}"
TARGET="${1:-127.0.0.1}"
PORTS="${PORTS:-22}"
SCOPE="${SCOPE:-authorized testing only}"
WINDOW="${WINDOW:-}"
NETWORK_PATH="${NETWORK_PATH:-external}"
RECON_INPUT_DIR="${RECON_INPUT_DIR:-}"

mkdir -p "${RUN_DIR}/task1"/{raw,json,evidence}

export PYTHONPATH="${TOOLS_DIR}/scripts"
export PROJECT_ROOT="${TOOLS_DIR}/.."

SCRIPTS="${TOOLS_DIR}/scripts"

python3 "${SCRIPTS}/build_manifests.py"          --run-dir "${RUN_DIR}" --task-id task1 --mode init
python3 "${SCRIPTS}/init_target_profile.py"      --run-dir "${RUN_DIR}" --target "${TARGET}" --ports "${PORTS}" --scope "${SCOPE}" --window "${WINDOW}" --network-path "${NETWORK_PATH}" --recon-input-dir "${RECON_INPUT_DIR}"
"${SCRIPTS}/collect_recon.sh"                    "${RUN_DIR}" "${TARGET}" "${PORTS}" "${RECON_INPUT_DIR}"
python3 "${SCRIPTS}/parse_recon.py"              --run-dir "${RUN_DIR}"
python3 "${SCRIPTS}/query_searchsploit.py"       --run-dir "${RUN_DIR}"
python3 "${SCRIPTS}/build_hypotheses.py"         --run-dir "${RUN_DIR}"
python3 "${SCRIPTS}/build_validation_plan.py"    --run-dir "${RUN_DIR}"
python3 "${SCRIPTS}/record_timeline.py"          --run-dir "${RUN_DIR}"
python3 "${SCRIPTS}/init_manual_validation_note.py" --run-dir "${RUN_DIR}"
python3 "${SCRIPTS}/build_validation_results.py" --run-dir "${RUN_DIR}"
python3 "${SCRIPTS}/build_evidence_index.py"     --run-dir "${RUN_DIR}"
python3 "${SCRIPTS}/build_report_context.py"     --run-dir "${RUN_DIR}"
python3 "${SCRIPTS}/render_reports.py"           --run-dir "${RUN_DIR}" --project-root "${TOOLS_DIR}/.."
python3 "${SCRIPTS}/build_manifests.py"          --run-dir "${RUN_DIR}" --task-id task1 --mode package

echo "[完成] 输出目录: ${RUN_DIR}"
