#!/bin/bash

# Setup script for samordningsyta2 Docker deployment
# Creates necessary directories and sets correct permissions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERSISTENT_DATA_ROOT="/mnt/data/projects/data"

echo "=== Samordningsyta2 Setup ==="
echo ""

# Create persistent data directories
echo "Creating persistent data directories..."
mkdir -p "${PERSISTENT_DATA_ROOT}/samordningsyta2/data"
mkdir -p "${PERSISTENT_DATA_ROOT}/samordningsyta2/uploads"

# Set correct ownership (matching Docker container user 1000:1000)
echo "Setting directory permissions..."
chown 1000:1000 "${PERSISTENT_DATA_ROOT}/samordningsyta2/data"
chown 1000:1000 "${PERSISTENT_DATA_ROOT}/samordningsyta2/uploads"

# Set correct permissions on existing database files if they exist
if [ -f "${PERSISTENT_DATA_ROOT}/samordningsyta2/data/app.db" ]; then
    echo "Setting permissions on existing database files..."
    chown 1000:1000 "${PERSISTENT_DATA_ROOT}/samordningsyta2/data/app.db"
    chown 1000:1000 "${PERSISTENT_DATA_ROOT}/samordningsyta2/data/app.db-shm" 2>/dev/null || true
    chown 1000:1000 "${PERSISTENT_DATA_ROOT}/samordningsyta2/data/app.db-wal" 2>/dev/null || true
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Directories created:"
echo "  - ${PERSISTENT_DATA_ROOT}/samordningsyta2/data"
echo "  - ${PERSISTENT_DATA_ROOT}/samordningsyta2/uploads"
echo ""
echo "Next steps:"
echo "  1. cd ${SCRIPT_DIR}"
echo "  2. docker compose build"
echo "  3. docker compose up -d"
