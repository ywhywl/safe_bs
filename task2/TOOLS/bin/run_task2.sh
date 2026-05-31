#!/usr/bin/env bash
# task2 — SFTP anomaly detection pipeline
# Self-contained: all scripts under TOOLS/scripts/, PYTHONPATH points here
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +"%Y%m%dT%H%M%SZ")}"
RUN_DIR="${PROJECT_ROOT}/runs/${RUN_ID}"
INPUT_DIR="${1:-${PROJECT_ROOT}/task2/TOOLS/samples}"

LLM_CONFIG="${LLM_CONFIG:-${TOOLS_DIR}/llm_config.json}"

mkdir -p "${RUN_DIR}/task2"/{json,alerts}

export PYTHONPATH="${TOOLS_DIR}/scripts"

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

run_step "ingest_logs" python3 ingest_logs.py --run-dir "${RUN_DIR}" --input-dir "${INPUT_DIR}"
run_step "normalize_events" python3 normalize_events.py --run-dir "${RUN_DIR}" --input-dir "${INPUT_DIR}"
run_step "reattribute_session_users" python3 reattribute_session_users.py --run-dir "${RUN_DIR}"
run_step "stage1_build_baseline" python3 stage1_build_baseline.py --run-dir "${RUN_DIR}"
run_step "stage1_detect_candidates" python3 stage1_detect_candidates.py --run-dir "${RUN_DIR}" --input-dir "${INPUT_DIR}"
run_step "extract_stage2_scope" python3 extract_stage2_scope.py --run-dir "${RUN_DIR}"
run_step "build_baseline" python3 build_baseline.py --run-dir "${RUN_DIR}"
run_step "score_anomalies" python3 score_anomalies.py --run-dir "${RUN_DIR}" --input-dir "${INPUT_DIR}"
run_step "build_session_views" python3 build_session_views.py --run-dir "${RUN_DIR}"
run_step "build_sequence_clusters" python3 build_sequence_clusters.py --run-dir "${RUN_DIR}"
run_step "build_alerts" python3 build_alerts.py --run-dir "${RUN_DIR}" --input-dir "${INPUT_DIR}"
run_step "emit_alert_log" python3 emit_alert_log.py --run-dir "${RUN_DIR}"
run_step "build_baseline_views" python3 build_baseline_views.py --run-dir "${RUN_DIR}"
run_step "build_report_context" python3 build_report_context.py --run-dir "${RUN_DIR}"
run_step "render_reports" python3 render_reports.py --run-dir "${RUN_DIR}" --project-root "${PROJECT_ROOT}" --llm-config "${LLM_CONFIG}"