#!/bin/bash

# Setup script for samordningsyta2 Docker deployment
# Creates necessary directories and sets correct permissions

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERSISTENT_DATA_ROOT="/mnt/data/projects/data"
cd "${SCRIPT_DIR}"

echo "=== Samordningsyta2 Setup ==="
echo ""

if [ -f "${SCRIPT_DIR}/.env" ]; then
    if grep -Eq '(^|[^A-Z])ENC\[' "${SCRIPT_DIR}/.env"; then
        echo "Decrypting .env with sops..."
        if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
            sudo -u "${SUDO_USER}" sops -d -i .env
        else
            sops -d -i .env
        fi
    else
        echo ".env appears already decrypted, skipping sops decrypt."
    fi
fi

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
ADMIN2_EMAIL=
ADMIN2_USERNAME=admin2
ADMIN2_PASSWORD=changeme90

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
    echo "Especially set: ADMIN_EMAIL/ADMIN_USERNAME + ADMIN_PASSWORD, ADMIN2_EMAIL/ADMIN2_USERNAME + ADMIN2_PASSWORD, SMTP_HOST, SMTP_PASS, MAIL_FROM"
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
echo "Building image without cache..."
docker compose build --no-cache

echo "Starting containers..."
docker compose up -d

echo ""
echo "Deployment complete."
