#!/usr/bin/env bash
set -euo pipefail

RUN_DIR="${1:?run dir required}"
TARGET="${2:-}"

RAW_DIR="${RUN_DIR}/task3/raw"
mkdir -p "${RAW_DIR}"

{
  echo "target=${TARGET}"
  echo "collected_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "note=readonly collection from multiple config files"
} > "${RAW_DIR}/readonly_meta.env"

if [[ -n "${TARGET}" && -f "${TARGET}" ]]; then
  cp "${TARGET}" "${RAW_DIR}/nginx_T.txt"
  exit 0
fi

if [[ -n "${TARGET}" && -d "${TARGET}" ]]; then
  cp -R "${TARGET}/." "${RAW_DIR}/"
  exit 0
fi

# If local nginx is available, collect live config
if command -v nginx >/dev/null 2>&1; then
  nginx -T > "${RAW_DIR}/nginx_T.txt" 2>"${RAW_DIR}/nginx_T.stderr" || true
  nginx -V > "${RAW_DIR}/nginx_V.txt" 2>&1 || true
  if [[ -s "${RAW_DIR}/nginx_T.txt" ]]; then
    exit 0
  fi
fi

# Fallback to bundled readonly evidence when no target file or local nginx config is available.
EVIDENCE_RAW="${PROJECT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}/task3/TOOLS/evidence/raw"
if [[ -d "${EVIDENCE_RAW}" ]]; then
  for f in "${EVIDENCE_RAW}"/ng*.conf "${EVIDENCE_RAW}"/ng*.txt; do
    if [[ -f "$f" ]]; then
      cp "$f" "${RAW_DIR}/"
    fi
  done
fi
