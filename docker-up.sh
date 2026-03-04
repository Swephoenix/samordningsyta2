#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "Building image without cache..."
docker compose build --no-cache

echo "Starting containers..."
docker compose up -d

echo "Done."
