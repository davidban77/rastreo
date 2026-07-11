#!/usr/bin/env bash
# Bootstrap NetBox for the rastreo consumer: custom fields, default
# manufacturer + device type + site + role. Idempotent.
#
# Expects NetBox healthy on http://localhost:8081 with the token seeded via
# docker-compose.yml.

set -euo pipefail

NETBOX_URL="${NETBOX_URL:-http://localhost:8081}"
NETBOX_TOKEN="${NETBOX_TOKEN:-abcdef0123456789abcdef0123456789abcdef01}"

curl_api() {
    curl -sf -H "Authorization: Token ${NETBOX_TOKEN}" -H "Content-Type: application/json" "$@"
}

get_or_create() {
    local endpoint="$1"
    local lookup_key="$2"
    local lookup_val="$3"
    local payload="$4"
    local existing
    existing=$(curl_api "${NETBOX_URL}/api/${endpoint}/?${lookup_key}=${lookup_val}" | jq -r '.results[0].id // empty')
    if [ -n "$existing" ]; then
        echo "  ${endpoint}: '${lookup_val}' exists (${existing})"
        return 0
    fi
    local created
    created=$(curl_api -X POST "${NETBOX_URL}/api/${endpoint}/" -d "$payload" | jq -r '.id')
    echo "  ${endpoint}: created '${lookup_val}' (${created})"
}

# NetBox 4.x custom_fields.object_types is `["dcim.device"]`.
OT='"dcim.device"'

echo "== custom fields on dcim.device =="

for field in \
    '{"name":"rastreo_identity_key","label":"rastreo identity key","type":"text","object_types":['"$OT"'],"unique":true}' \
    '{"name":"rastreo_last_seen","label":"rastreo last seen","type":"datetime","object_types":['"$OT"']}' \
    '{"name":"rastreo_confidence","label":"rastreo confidence","type":"decimal","object_types":['"$OT"']}' \
    '{"name":"rastreo_os_version","label":"rastreo OS version","type":"text","object_types":['"$OT"']}' \
    '{"name":"rastreo_ssh_version","label":"rastreo SSH version","type":"text","object_types":['"$OT"']}' \
    '{"name":"rastreo_http_server","label":"rastreo HTTP server","type":"text","object_types":['"$OT"']}' \
    '{"name":"rastreo_http_version","label":"rastreo HTTP version","type":"text","object_types":['"$OT"']}' \
    '{"name":"rastreo_signals","label":"rastreo signals","type":"json","object_types":['"$OT"']}' \
    '{"name":"rastreo_probe_kinds","label":"rastreo probe kinds","type":"json","object_types":['"$OT"']}' \
    '{"name":"rastreo_alt_ips","label":"rastreo alt ips","type":"json","object_types":['"$OT"']}' \
    '{"name":"rastreo_scan_metadata","label":"rastreo scan metadata","type":"json","object_types":['"$OT"']}'
do
    name=$(echo "$field" | jq -r '.name')
    get_or_create "extras/custom-fields" "name" "$name" "$field"
done

echo "== default manufacturer =="
get_or_create "dcim/manufacturers" "name" "Rastreo" \
    '{"name":"Rastreo","slug":"rastreo"}'

MFR_ID=$(curl_api "${NETBOX_URL}/api/dcim/manufacturers/?name=Rastreo" | jq -r '.results[0].id')

echo "== default device-type =="
get_or_create "dcim/device-types" "model" "rastreo-generic" \
    '{"model":"rastreo-generic","slug":"rastreo-generic","manufacturer":'"$MFR_ID"',"u_height":1}'

echo "== default role =="
get_or_create "dcim/device-roles" "name" "rastreo-discovered" \
    '{"name":"rastreo-discovered","slug":"rastreo-discovered","color":"9e9e9e"}'

echo "== default site =="
get_or_create "dcim/sites" "name" "rastreo-lab" \
    '{"name":"rastreo-lab","slug":"rastreo-lab","status":"active"}'

echo
echo "Bootstrap complete. NetBox ready for the rastreo consumer."
