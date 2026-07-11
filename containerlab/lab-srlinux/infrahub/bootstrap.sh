#!/usr/bin/env bash
# Bootstrap Infrahub for the rastreo consumer: load the RastreoDevice schema
# from examples/infrahub-consumer/infrahub-schema.yaml. Idempotent — the
# schema-load endpoint is a merge.
#
# Expects Infrahub healthy on http://localhost:8082 with the token seeded via
# docker-compose.yml.

set -euo pipefail

INFRAHUB_URL="${INFRAHUB_URL:-http://localhost:8082}"
INFRAHUB_TOKEN="${INFRAHUB_TOKEN:-06438eb2-8019-4776-878c-0941b1f1d1ec}"
SCHEMA_FILE="${SCHEMA_FILE:-../../../examples/infrahub-consumer/infrahub-schema.yaml}"

if [ ! -f "$SCHEMA_FILE" ]; then
    echo "ERROR: schema file not found at $SCHEMA_FILE" >&2
    exit 1
fi

echo "== loading schema from ${SCHEMA_FILE} =="

# Infrahub 1.x accepts schema uploads via /api/schema/load — POST a YAML body
# with the header saying yaml. On success returns 200 with schema changes.
curl -sf \
    -X POST \
    -H "X-INFRAHUB-KEY: ${INFRAHUB_TOKEN}" \
    -H "Content-Type: application/yaml" \
    --data-binary "@${SCHEMA_FILE}" \
    "${INFRAHUB_URL}/api/schema/load?branch=main" \
    | jq . || {
        echo "ERROR: schema load failed. Verify infrahub is healthy and token is valid." >&2
        exit 1
    }

echo
echo "Bootstrap complete. Infrahub ready for the rastreo consumer."
echo "The consumer will create branch 'rastreo-updates' on first message."
