#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +"%Y%m%dT%H%M%SZ")}"
RUN_DIR="${PROJECT_ROOT}/runs/${RUN_ID}"
INPUT_DIR="${1:-${PROJECT_ROOT}/task2/TOOLS/samples}"

# LLM 配置：默认外网模式，设置 LLM_CONFIG 内网配置路径后切换
LLM_CONFIG="${LLM_CONFIG:-${PROJECT_ROOT}/task2/TOOLS/llm_config.json}"

mkdir -p "${RUN_DIR}/task2"/{json,alerts}

export PYTHONPATH="${PROJECT_ROOT}/scripts/common"

python3 "${PROJECT_ROOT}/scripts/common/build_manifests.py" --run-dir "${RUN_DIR}" --task-id task2 --mode init
python3 "${PROJECT_ROOT}/scripts/task2/ingest_logs.py" --run-dir "${RUN_DIR}" --input-dir "${INPUT_DIR}"
python3 "${PROJECT_ROOT}/scripts/task2/normalize_events.py" --run-dir "${RUN_DIR}" --input-dir "${INPUT_DIR}"
python3 "${PROJECT_ROOT}/scripts/task2/build_baseline.py" --run-dir "${RUN_DIR}"
python3 "${PROJECT_ROOT}/scripts/task2/score_anomalies.py" --run-dir "${RUN_DIR}" --input-dir "${INPUT_DIR}"
python3 "${PROJECT_ROOT}/scripts/task2/build_session_views.py" --run-dir "${RUN_DIR}"
python3 "${PROJECT_ROOT}/scripts/task2/build_alerts.py" --run-dir "${RUN_DIR}" --input-dir "${INPUT_DIR}"
python3 "${PROJECT_ROOT}/scripts/task2/emit_alert_log.py" --run-dir "${RUN_DIR}"
python3 "${PROJECT_ROOT}/scripts/task2/build_baseline_views.py" --run-dir "${RUN_DIR}"
python3 "${PROJECT_ROOT}/scripts/task2/build_report_context.py" --run-dir "${RUN_DIR}"
python3 "${PROJECT_ROOT}/scripts/task2/render_reports.py" --run-dir "${RUN_DIR}" --project-root "${PROJECT_ROOT}" --llm-config "${LLM_CONFIG}"
python3 "${PROJECT_ROOT}/scripts/common/build_manifests.py" --run-dir "${RUN_DIR}" --task-id task2 --mode package
python3 "${PROJECT_ROOT}/scripts/common/sync_deliverables.py" --run-dir "${RUN_DIR}" --project-root "${PROJECT_ROOT}" --task-id task2
