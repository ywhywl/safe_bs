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

STEP_LOG="${RUN_DIR}/task2/alerts/step_timing.log"

log_step() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" | tee -a "${STEP_LOG}"
}

run_step() {
  local step_name="$1"
  shift
  local start_epoch
  start_epoch="$(date +%s)"
  log_step "START ${step_name}"
  "$@"
  local end_epoch
  end_epoch="$(date +%s)"
  log_step "DONE  ${step_name} ($((end_epoch - start_epoch))s)"
}

log_step "RUN_ID=${RUN_ID}"
log_step "INPUT_DIR=${INPUT_DIR}"
log_step "LLM_CONFIG=${LLM_CONFIG}"

run_step "build_manifests:init" python3 "${PROJECT_ROOT}/scripts/common/build_manifests.py" --run-dir "${RUN_DIR}" --task-id task2 --mode init
run_step "ingest_logs" python3 "${PROJECT_ROOT}/scripts/task2/ingest_logs.py" --run-dir "${RUN_DIR}" --input-dir "${INPUT_DIR}"
run_step "normalize_events" python3 "${PROJECT_ROOT}/scripts/task2/normalize_events.py" --run-dir "${RUN_DIR}" --input-dir "${INPUT_DIR}"
run_step "build_baseline" python3 "${PROJECT_ROOT}/scripts/task2/build_baseline.py" --run-dir "${RUN_DIR}"
run_step "score_anomalies" python3 "${PROJECT_ROOT}/scripts/task2/score_anomalies.py" --run-dir "${RUN_DIR}" --input-dir "${INPUT_DIR}"
run_step "build_session_views" python3 "${PROJECT_ROOT}/scripts/task2/build_session_views.py" --run-dir "${RUN_DIR}"
run_step "build_sequence_clusters" python3 "${PROJECT_ROOT}/scripts/task2/build_sequence_clusters.py" --run-dir "${RUN_DIR}"
run_step "build_alerts" python3 "${PROJECT_ROOT}/scripts/task2/build_alerts.py" --run-dir "${RUN_DIR}" --input-dir "${INPUT_DIR}"
run_step "emit_alert_log" python3 "${PROJECT_ROOT}/scripts/task2/emit_alert_log.py" --run-dir "${RUN_DIR}"
run_step "build_baseline_views" python3 "${PROJECT_ROOT}/scripts/task2/build_baseline_views.py" --run-dir "${RUN_DIR}"
run_step "build_report_context" python3 "${PROJECT_ROOT}/scripts/task2/build_report_context.py" --run-dir "${RUN_DIR}"
run_step "render_reports" python3 "${PROJECT_ROOT}/scripts/task2/render_reports.py" --run-dir "${RUN_DIR}" --project-root "${PROJECT_ROOT}" --llm-config "${LLM_CONFIG}"
run_step "build_manifests:package" python3 "${PROJECT_ROOT}/scripts/common/build_manifests.py" --run-dir "${RUN_DIR}" --task-id task2 --mode package
run_step "sync_deliverables" python3 "${PROJECT_ROOT}/scripts/common/sync_deliverables.py" --run-dir "${RUN_DIR}" --project-root "${PROJECT_ROOT}" --task-id task2
