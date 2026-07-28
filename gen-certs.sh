#!/usr/bin/env bash
# Generate a local self-signed certificate for the sensor.
set -euo pipefail

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt \
  -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Created server.crt and server.key"
