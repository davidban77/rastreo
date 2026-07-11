#!/usr/bin/env bash
# Bootstrap Infrahub for the rastreo consumer: load the RastreoDevice schema
# from examples/infrahub-consumer/infrahub-schema.yaml via `infrahubctl` from
# inside the running infrahub container. Idempotent — the schema-load path
# is a merge.
#
# Expects the `rastreo-lab-infrahub` container running and healthy (see
# docker-compose.yml).

set -euo pipefail

INFRAHUB_CONTAINER="${INFRAHUB_CONTAINER:-rastreo-lab-infrahub}"
INFRAHUB_TOKEN="${INFRAHUB_TOKEN:-06438eb2-8019-4776-878c-0941b1f1d1ec}"
SCHEMA_FILE="${SCHEMA_FILE:-../../../examples/infrahub-consumer/infrahub-schema.yaml}"

if [ ! -f "$SCHEMA_FILE" ]; then
    echo "ERROR: schema file not found at $SCHEMA_FILE" >&2
    exit 1
fi

echo "== loading schema from ${SCHEMA_FILE} into infrahub =="

docker cp "$SCHEMA_FILE" "${INFRAHUB_CONTAINER}:/tmp/schema.yaml"
docker exec \
    -e "INFRAHUB_ADDRESS=http://localhost:8000" \
    -e "INFRAHUB_API_TOKEN=${INFRAHUB_TOKEN}" \
    "$INFRAHUB_CONTAINER" \
    infrahubctl schema load /tmp/schema.yaml

echo
echo "Bootstrap complete. Infrahub ready for the rastreo consumer."
echo "The consumer will create branch 'rastreo-updates' on first message."
