#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PROJECT_ROOT
RUN_ID="${RUN_ID:-$(date -u +"%Y%m%dT%H%M%SZ")}"
RUN_DIR="${PROJECT_ROOT}/runs/${RUN_ID}"
TARGET="${1:-localhost}"

# LLM 配置：默认外网模式，设置 LLM_CONFIG 内网配置路径后切换
LLM_CONFIG="${LLM_CONFIG:-${PROJECT_ROOT}/task3/TOOLS/llm_config.json}"

mkdir -p "${RUN_DIR}/task3"/{raw,json,evidence}

export PYTHONPATH="${PROJECT_ROOT}/scripts/common"

python3 "${PROJECT_ROOT}/scripts/common/build_manifests.py" --run-dir "${RUN_DIR}" --task-id task3 --mode init
"${PROJECT_ROOT}/scripts/task3/collect_readonly.sh" "${RUN_DIR}" "${TARGET}"
python3 "${PROJECT_ROOT}/scripts/task3/build_inventory.py" --run-dir "${RUN_DIR}" --target "${TARGET}"
python3 "${PROJECT_ROOT}/scripts/task3/parse_config_facts.py" --run-dir "${RUN_DIR}"
python3 "${PROJECT_ROOT}/scripts/task3/apply_rules.py" --run-dir "${RUN_DIR}" --rules "${PROJECT_ROOT}/task3/TOOLS/rules/nginx_rules.json"
python3 "${PROJECT_ROOT}/scripts/task3/build_risk_register.py" --run-dir "${RUN_DIR}"
python3 "${PROJECT_ROOT}/scripts/task3/build_report_context.py" --run-dir "${RUN_DIR}"
python3 "${PROJECT_ROOT}/scripts/task3/render_reports.py" --run-dir "${RUN_DIR}" --project-root "${PROJECT_ROOT}" --llm-config "${LLM_CONFIG}"
python3 "${PROJECT_ROOT}/scripts/common/build_manifests.py" --run-dir "${RUN_DIR}" --task-id task3 --mode package
python3 "${PROJECT_ROOT}/scripts/common/sync_deliverables.py" --run-dir "${RUN_DIR}" --project-root "${PROJECT_ROOT}" --task-id task3
