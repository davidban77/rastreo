#!/usr/bin/env bash
# Downloads the latest Wireshark manuf file, gzips it, and writes the result
# to rastreo-core/data/manuf.gz. Prints the source URL, HTTP Last-Modified
# header, and SHA-256 of the compressed artifact so the provenance can be
# recorded in the PR description and docs.
#
# Source: https://www.wireshark.org/download/automated/data/manuf
# License of the data itself: CC0-1.0 (see the manuf file's own header).
#
# Usage:
#   scripts/refresh-oui.sh
#
# The Wireshark manuf file is regenerated once a week upstream. Do not run
# this script more often than that (see the file's own comment header).
set -euo pipefail

SOURCE_URL="https://www.wireshark.org/download/automated/data/manuf"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${REPO_ROOT}/rastreo-core/data"
OUT_FILE="${OUT_DIR}/manuf.gz"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${OUT_DIR}"

echo "Downloading ${SOURCE_URL} ..."
curl -fsSL --retry 3 -D "${TMP_DIR}/headers.txt" -o "${TMP_DIR}/manuf.txt" "${SOURCE_URL}"

LAST_MODIFIED="$(awk 'BEGIN{IGNORECASE=1} /^last-modified:/ {sub(/^[^:]*: */, ""); sub(/\r$/, ""); print; exit}' "${TMP_DIR}/headers.txt")"
LINE_COUNT="$(wc -l < "${TMP_DIR}/manuf.txt" | tr -d ' ')"

gzip -9 -c "${TMP_DIR}/manuf.txt" > "${OUT_FILE}"

if command -v sha256sum >/dev/null 2>&1; then
    SHA="$(sha256sum "${OUT_FILE}" | awk '{print $1}')"
else
    SHA="$(shasum -a 256 "${OUT_FILE}" | awk '{print $1}')"
fi

BYTES="$(wc -c < "${OUT_FILE}" | tr -d ' ')"

echo
echo "Wrote ${OUT_FILE}"
echo "  source:        ${SOURCE_URL}"
echo "  last-modified: ${LAST_MODIFIED:-<unknown>}"
echo "  line count:    ${LINE_COUNT}"
echo "  gz size:       ${BYTES} bytes"
echo "  sha-256:       ${SHA}"
