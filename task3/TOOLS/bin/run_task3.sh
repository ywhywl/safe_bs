#!/usr/bin/env bash
# task3 — Nginx config audit pipeline
# Self-contained: all scripts under TOOLS/scripts/, PYTHONPATH points here
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export PROJECT_ROOT
RUN_ID="${RUN_ID:-$(date -u +"%Y%m%dT%H%M%SZ")}"
RUN_DIR="${PROJECT_ROOT}/runs/${RUN_ID}"
TARGET="${1:-localhost}"

LLM_CONFIG="${LLM_CONFIG:-${TOOLS_DIR}/llm_config.json}"

mkdir -p "${RUN_DIR}/task3"/{raw,json,evidence}

export PYTHONPATH="${TOOLS_DIR}/scripts"

python3 build_inventory.py --run-dir "${RUN_DIR}" --target "${TARGET}"
"${TOOLS_DIR}/scripts/collect_readonly.sh" "${RUN_DIR}" "${TARGET}"
python3 parse_config_facts.py --run-dir "${RUN_DIR}"
python3 apply_rules.py --run-dir "${RUN_DIR}" --rules "${TOOLS_DIR}/rules/nginx_rules.json"
python3 build_risk_register.py --run-dir "${RUN_DIR}"
python3 build_report_context.py --run-dir "${RUN_DIR}"
python3 render_reports.py --run-dir "${RUN_DIR}" --project-root "${PROJECT_ROOT}" --llm-config "${LLM_CONFIG}"