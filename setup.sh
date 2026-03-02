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
sudo chown 1000:1000 "${PERSISTENT_DATA_ROOT}/samordningsyta2/data"
sudo chown 1000:1000 "${PERSISTENT_DATA_ROOT}/samordningsyta2/uploads"

# Set correct permissions on existing database files if they exist
if [ -f "${PERSISTENT_DATA_ROOT}/samordningsyta2/data/app.db" ]; then
    echo "Setting permissions on existing database files..."
    sudo chown 1000:1000 "${PERSISTENT_DATA_ROOT}/samordningsyta2/data/app.db"
    sudo chown 1000:1000 "${PERSISTENT_DATA_ROOT}/samordningsyta2/data/app.db-shm" 2>/dev/null || true
    sudo chown 1000:1000 "${PERSISTENT_DATA_ROOT}/samordningsyta2/data/app.db-wal" 2>/dev/null || true
fi

# Set correct permissions on existing uploads subdirectories
if [ -d "${PERSISTENT_DATA_ROOT}/samordningsyta2/uploads" ]; then
    echo "Setting permissions on uploads directory..."
    sudo chown -R 1000:1000 "${PERSISTENT_DATA_ROOT}/samordningsyta2/uploads"
fi

# Generate .env file if it doesn't exist
if [ ! -f "${SCRIPT_DIR}/.env" ]; then
    echo "Generating .env file..."
    
    # Generate random session secret (32 characters)
    SESSION_SECRET=$(openssl rand -hex 16 2>/dev/null || cat /proc/sys/kernel/random/uuid | tr -d '-')
    
    cat > "${SCRIPT_DIR}/.env" << EOF
ADMIN_EMAIL=
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme89
ADMIN_NAME=Admin

SMTP_HOST=
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=noreply
SMTP_PASS=
MAIL_FROM=

# Persistent storage root (bind mounts)
PERSISTENT_DATA_ROOT=${PERSISTENT_DATA_ROOT}

# Application
APP_PORT=8000
PORT=8000
NODE_ENV=development

SESSION_SECRET=${SESSION_SECRET}
EOF
    
    echo "WARNING: Please review and update ${SCRIPT_DIR}/.env with your settings!"
    echo "Especially set: ADMIN_EMAIL, SMTP_HOST, SMTP_PASS, MAIL_FROM"
else
    echo ".env file already exists, skipping creation."
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
