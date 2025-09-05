#!/usr/bin/env bash
# curl_tests.sh — tests for SMS package endpoints
# Usage: set BASE_URL and AUTH cookie or header as needed
# Example:
#  export BASE_URL="http://localhost:3000"
#  export AUTH_HEADER="Cookie: session=..."
#  ./curl_tests.sh

BASE="${BASE_URL:-http://localhost:3000}"
AUTH="${AUTH_HEADER:-}"

echo "1) Get users"
curl -s -X GET "${BASE}/api/admin/users" -H "Accept: application/json" -H "$AUTH" | jq '.' || true
echo
echo "2) Grant 25 SMS to user USER_ID (replace USER_ID)"
USER_ID="${1:-REPLACE_WITH_USER_ID}"
curl -s -X POST "${BASE}/api/admin/consume-package" -H "Content-Type: application/json" -H "$AUTH"   -d "{"userId":"${USER_ID}","qty":25,"note":"test grant"}" | jq '.' || true
echo
echo "3) Get history"
curl -s -X GET "${BASE}/api/admin/sms-packages/history" -H "Accept: application/json" -H "$AUTH" | jq '.' || true
echo
echo "Done."
