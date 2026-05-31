#!/usr/bin/env bash
# task1 — Vulnerability assessment pipeline
# Self-contained: cd into TOOLS/scripts/, PYTHONPATH points here
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +"%Y%m%dT%H%M%SZ")}"
RUN_DIR="${PROJECT_ROOT}/runs/${RUN_ID}"
TARGET="${1:-127.0.0.1}"
PORTS="${PORTS:-22}"
SCOPE="${SCOPE:-authorized testing only}"
WINDOW="${WINDOW:-}"
NETWORK_PATH="${NETWORK_PATH:-external}"
RECON_INPUT_DIR="${RECON_INPUT_DIR:-}"

mkdir -p "${RUN_DIR}/task1"/{raw,json,evidence}

cd "${TOOLS_DIR}/scripts"
export PYTHONPATH="${TOOLS_DIR}/scripts"

python3 build_manifests.py --run-dir "${RUN_DIR}" --task-id task1 --mode init
python3 init_target_profile.py --run-dir "${RUN_DIR}" --target "${TARGET}" --ports "${PORTS}" --scope "${SCOPE}" --window "${WINDOW}" --network-path "${NETWORK_PATH}" --recon-input-dir "${RECON_INPUT_DIR}"
bash collect_recon.sh "${RUN_DIR}" "${TARGET}" "${PORTS}" "${RECON_INPUT_DIR}"
python3 parse_recon.py --run-dir "${RUN_DIR}"
python3 query_searchsploit.py --run-dir "${RUN_DIR}"
python3 build_hypotheses.py --run-dir "${RUN_DIR}"
python3 build_validation_plan.py --run-dir "${RUN_DIR}"
python3 record_timeline.py --run-dir "${RUN_DIR}"
python3 init_manual_validation_note.py --run-dir "${RUN_DIR}"
python3 build_validation_results.py --run-dir "${RUN_DIR}"
python3 build_evidence_index.py --run-dir "${RUN_DIR}"
python3 build_report_context.py --run-dir "${RUN_DIR}"
python3 render_reports.py --run-dir "${RUN_DIR}" --project-root "${PROJECT_ROOT}"
python3 build_manifests.py --run-dir "${RUN_DIR}" --task-id task1 --mode package
python3 sync_deliverables.py --run-dir "${RUN_DIR}" --project-root "${PROJECT_ROOT}" --task-id task1