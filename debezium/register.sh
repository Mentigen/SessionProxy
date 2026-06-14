#!/bin/sh
set -e

CONNECT_URL="${CONNECT_URL:-http://localhost:8083}"

echo "Waiting for Kafka Connect at $CONNECT_URL ..."
until curl -sf "$CONNECT_URL/connectors" > /dev/null; do
  sleep 5
done
echo "Kafka Connect is up."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

curl -s -X PUT "$CONNECT_URL/connectors/postgres-connector/config" \
  -H "Content-Type: application/json" \
  -d @"$SCRIPT_DIR/connector.json"
echo
echo "Connector registered. Status:"
curl -s "$CONNECT_URL/connectors/postgres-connector/status" | python3 -m json.tool 2>/dev/null || true
