#!/usr/bin/env bash
# Bootstrap Nautobot for the rastreo consumer: custom fields, default device
# type, default location, default status. Idempotent — safe to re-run.
#
# Expects Nautobot to already be healthy on http://localhost:8080 with the
# superuser API token from docker-compose.yml.

set -euo pipefail

NAUTOBOT_URL="${NAUTOBOT_URL:-http://localhost:8080}"
NAUTOBOT_TOKEN="${NAUTOBOT_TOKEN:-0123456789abcdef0123456789abcdef01234567}"

curl_api() {
    curl -sf -H "Authorization: Token ${NAUTOBOT_TOKEN}" -H "Content-Type: application/json" "$@"
}

get_or_create() {
    local endpoint="$1"
    local lookup_key="$2"
    local lookup_val="$3"
    local payload="$4"
    local existing
    existing=$(curl_api "${NAUTOBOT_URL}/api/${endpoint}/?limit=500" \
        | jq -r --arg key "${lookup_key}" --arg val "${lookup_val}" '.results[] | select(.[$key] == $val) | .id' \
        | head -1)
    if [ -n "$existing" ]; then
        echo "  ${endpoint}: '${lookup_val}' exists (${existing})"
        return 0
    fi
    local created
    created=$(curl_api -X POST "${NAUTOBOT_URL}/api/${endpoint}/" -d "$payload" | jq -r '.id')
    echo "  ${endpoint}: created '${lookup_val}' (${created})"
}

# Object types Nautobot expects for the custom-field content_type binding.
DCIM_DEVICE_CT='"dcim.device"'

echo "== custom fields on dcim.device =="

for field in \
    '{"key":"rastreo_identity_key","label":"Rastreo Identity Key","type":"text","required":false,"content_types":['"$DCIM_DEVICE_CT"']}' \
    '{"key":"rastreo_last_seen","label":"Rastreo Last Seen","type":"text","required":false,"content_types":['"$DCIM_DEVICE_CT"']}' \
    '{"key":"rastreo_confidence","label":"Rastreo Confidence","type":"text","required":false,"content_types":['"$DCIM_DEVICE_CT"']}' \
    '{"key":"rastreo_os_version","label":"Rastreo OS Version","type":"text","required":false,"content_types":['"$DCIM_DEVICE_CT"']}' \
    '{"key":"rastreo_ssh_version","label":"Rastreo SSH Version","type":"text","required":false,"content_types":['"$DCIM_DEVICE_CT"']}' \
    '{"key":"rastreo_http_server","label":"Rastreo HTTP Server","type":"text","required":false,"content_types":['"$DCIM_DEVICE_CT"']}' \
    '{"key":"rastreo_http_version","label":"Rastreo HTTP Version","type":"text","required":false,"content_types":['"$DCIM_DEVICE_CT"']}' \
    '{"key":"rastreo_signals","label":"Rastreo Signals","type":"json","required":false,"content_types":['"$DCIM_DEVICE_CT"']}' \
    '{"key":"rastreo_probe_kinds","label":"Rastreo Probe Kinds","type":"json","required":false,"content_types":['"$DCIM_DEVICE_CT"']}' \
    '{"key":"rastreo_alt_ips","label":"Rastreo Alt IPs","type":"json","required":false,"content_types":['"$DCIM_DEVICE_CT"']}' \
    '{"key":"rastreo_scan_metadata","label":"Rastreo Scan Metadata","type":"json","required":false,"content_types":['"$DCIM_DEVICE_CT"']}'
do
    key=$(echo "$field" | jq -r '.key')
    get_or_create "extras/custom-fields" "key" "$key" "$field"
done

echo "== default manufacturer =="
get_or_create "dcim/manufacturers" "name" "Rastreo" \
    '{"name":"Rastreo","description":"Placeholder manufacturer for rastreo-discovered devices"}'

MFR_ID=$(curl_api "${NAUTOBOT_URL}/api/dcim/manufacturers/?name=Rastreo" | jq -r '.results[0].id')

echo "== default device-type =="
get_or_create "dcim/device-types" "model" "rastreo-generic" \
    '{"model":"rastreo-generic","manufacturer":"'"$MFR_ID"'","u_height":1}'

echo "== location type =="
get_or_create "dcim/location-types" "name" "Lab" \
    '{"name":"Lab","content_types":['"$DCIM_DEVICE_CT"']}'

LOC_TYPE_ID=$(curl_api "${NAUTOBOT_URL}/api/dcim/location-types/?name=Lab" | jq -r '.results[0].id')
STATUS_ID=$(curl_api "${NAUTOBOT_URL}/api/extras/statuses/?name=Active" | jq -r '.results[0].id')

echo "== default location =="
get_or_create "dcim/locations" "name" "rastreo-lab" \
    '{"name":"rastreo-lab","location_type":"'"$LOC_TYPE_ID"'","status":"'"$STATUS_ID"'"}'

echo "== default role =="
get_or_create "extras/roles" "name" "rastreo-discovered" \
    '{"name":"rastreo-discovered","color":"9e9e9e","content_types":['"$DCIM_DEVICE_CT"']}'

echo
echo "Bootstrap complete. Nautobot ready for the rastreo consumer."
