#!/usr/bin/env bash
set -euo pipefail

RUN_DIR="${1:?run dir required}"
TARGET="${2:?target required}"
PORTS="${3:-21,22}"
RECON_INPUT_DIR="${4:-}"

RAW_DIR="${RUN_DIR}/task1/raw"
mkdir -p "${RAW_DIR}"

NMAP_BIN="$(command -v nmap || true)"
SEARCHSPLOIT_BIN="$(command -v searchsploit || true)"
if [[ -z "${SEARCHSPLOIT_BIN}" && -x "/Users/wenlongy/dev/src/exploitdb/searchsploit" ]]; then
  SEARCHSPLOIT_BIN="/Users/wenlongy/dev/src/exploitdb/searchsploit"
fi

{
  echo "target=${TARGET}"
  echo "ports=${PORTS}"
  echo "collected_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "nmap_bin=${NMAP_BIN}"
  echo "searchsploit_bin=${SEARCHSPLOIT_BIN}"
  echo "collection_mode=$([[ -n "${RECON_INPUT_DIR}" ]] && echo imported_scan || echo active_recon)"
  echo "recon_input_dir=${RECON_INPUT_DIR}"
} > "${RAW_DIR}/recon_meta.env"

if [[ -n "${RECON_INPUT_DIR}" && -d "${RECON_INPUT_DIR}" ]]; then
  for path in "${RECON_INPUT_DIR}"/*; do
    if [[ -f "${path}" ]]; then
      cp "${path}" "${RAW_DIR}/$(basename "${path}")"
    fi
  done
  exit 0
fi

if [[ -n "${NMAP_BIN}" ]]; then
  "${NMAP_BIN}" -Pn -sV -p "${PORTS}" --version-light "${TARGET}" > "${RAW_DIR}/nmap.txt" 2>&1 || true
fi

if command -v nc >/dev/null 2>&1; then
  IFS=',' read -r -a port_array <<< "${PORTS}"
  for port in "${port_array[@]}"; do
    port_trimmed="$(echo "${port}" | xargs)"
    if [[ "${port_trimmed}" == "21" ]]; then
      printf 'QUIT\r\n' | nc -w 5 "${TARGET}" "${port_trimmed}" > "${RAW_DIR}/ftp_banner.txt" 2>&1 || true
    elif [[ "${port_trimmed}" == "22" ]]; then
      printf 'QUIT\r\n' | nc -w 5 "${TARGET}" "${port_trimmed}" > "${RAW_DIR}/ssh_banner.txt" 2>&1 || true
    else
      printf '\r\n' | nc -w 5 "${TARGET}" "${port_trimmed}" > "${RAW_DIR}/port_${port_trimmed}.txt" 2>&1 || true
    fi
  done
fi

if [[ -n "${SEARCHSPLOIT_BIN}" ]]; then
  "${SEARCHSPLOIT_BIN}" --json "ProFTPD 1.3.5" > "${RAW_DIR}/searchsploit_proftpd.json" 2>/dev/null || true
  "${SEARCHSPLOIT_BIN}" --json "SFTP" > "${RAW_DIR}/searchsploit_sftp.json" 2>/dev/null || true
fi
