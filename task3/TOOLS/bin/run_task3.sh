#!/usr/bin/env bash
# task3 — Nginx config audit pipeline
# Self-contained: cd into TOOLS/scripts/, PYTHONPATH points here
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export PROJECT_ROOT
RUN_ID="${RUN_ID:-$(date -u +"%Y%m%dT%H%M%SZ")}"
RUN_DIR="${PROJECT_ROOT}/runs/${RUN_ID}"
TARGET="${1:-localhost}"

LLM_CONFIG="${LLM_CONFIG:-${TOOLS_DIR}/llm_config.json}"

mkdir -p "${RUN_DIR}/task3"/{raw,json,evidence}

cd "${TOOLS_DIR}/scripts"
export PYTHONPATH="${TOOLS_DIR}/scripts"

python3 build_manifests.py --run-dir "${RUN_DIR}" --task-id task3 --mode init
python3 build_inventory.py --run-dir "${RUN_DIR}" --target "${TARGET}"
bash collect_readonly.sh "${RUN_DIR}" "${TARGET}"
python3 parse_config_facts.py --run-dir "${RUN_DIR}"
python3 apply_rules.py --run-dir "${RUN_DIR}" --rules "${TOOLS_DIR}/rules/nginx_rules.json"
python3 build_risk_register.py --run-dir "${RUN_DIR}"
python3 build_report_context.py --run-dir "${RUN_DIR}"
python3 render_reports.py --run-dir "${RUN_DIR}" --project-root "${PROJECT_ROOT}" --llm-config "${LLM_CONFIG}"
python3 build_manifests.py --run-dir "${RUN_DIR}" --task-id task3 --mode package
python3 sync_deliverables.py --run-dir "${RUN_DIR}" --project-root "${PROJECT_ROOT}" --task-id task3