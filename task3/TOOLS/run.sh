#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_ID="${RUN_ID:-$(date -u +"%Y%m%dT%H%M%SZ")}"
RUN_DIR="${TOOLS_DIR}/runs/${RUN_ID}"
TARGET="${1:-localhost}"
LLM_CONFIG="${LLM_CONFIG:-${TOOLS_DIR}/llm_config.json}"

mkdir -p "${RUN_DIR}/task3"/{raw,json,evidence}

export PYTHONPATH="${TOOLS_DIR}/scripts"
export PROJECT_ROOT="${TOOLS_DIR}/.."

SCRIPTS="${TOOLS_DIR}/scripts"

python3 "${SCRIPTS}/build_manifests.py"      --run-dir "${RUN_DIR}" --task-id task3 --mode init
"${SCRIPTS}/collect_readonly.sh"             "${RUN_DIR}" "${TARGET}"
python3 "${SCRIPTS}/build_inventory.py"      --run-dir "${RUN_DIR}" --target "${TARGET}"
python3 "${SCRIPTS}/parse_config_facts.py"   --run-dir "${RUN_DIR}"
python3 "${SCRIPTS}/apply_rules.py"          --run-dir "${RUN_DIR}" --rules "${TOOLS_DIR}/rules/nginx_rules.json"
python3 "${SCRIPTS}/build_risk_register.py"  --run-dir "${RUN_DIR}"
python3 "${SCRIPTS}/build_report_context.py" --run-dir "${RUN_DIR}"
python3 "${SCRIPTS}/render_reports.py"       --run-dir "${RUN_DIR}" --project-root "${TOOLS_DIR}/.." --llm-config "${LLM_CONFIG}"
python3 "${SCRIPTS}/build_manifests.py"      --run-dir "${RUN_DIR}" --task-id task3 --mode package

echo "[完成] 输出目录: ${RUN_DIR}"
