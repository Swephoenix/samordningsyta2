# Samordningsyta 2 - Project Context

This project is a coordination platform ("Samordningsyta") for the organization **Ambition Sverige**. It provides a central dashboard for members to communicate, manage tasks, view events, and access internal resources.

## Project Overview

- **Purpose:** Internal coordination, communication, and resource sharing for political/organizational activities.
- **Architecture:** Monolithic Node.js application using Express for the backend and Vanilla HTML/CSS/JS for the frontend.
- **Database:** SQLite (managed via `better-sqlite3`) for persistent storage.
- **Deployment:** Docker-ready with `docker-compose.yml` and `Dockerfile`.

## Core Features

- **Authentication & Roles:** Secure login system with roles including `user`, `secretary`, `admin`, and `IT-admin`.
- **Chat System:** Supports group chats, direct messages, file attachments, message pinning, and threaded replies.
- **Dashboard:**
    - **Important Messages:** High-priority announcements.
    - **Event Calendar:** Schedule of upcoming meetings and activities.
    - **Task Management:** Assignment and tracking of tasks.
    - **Notes:** Personal persistent notes for users.
- **Rule Book (Wiki):** An internal database of organizational rules and guidelines.
- **Media Academy:** Resources and links for social media growth (specifically Facebook).
- **File System:** A virtual file explorer for shared and private documents.
- **Member Management:** Administrative tools for user oversight.

## Technical Stack

- **Backend:** Node.js, Express.
- **Database:** SQLite (`better-sqlite3`).
- **Frontend:** Vanilla JavaScript, CSS (embedded in HTML files), Font: DM Sans, Lora.
- **Infrastructure:** Docker, Docker Compose, Bash (setup scripts).

## Building and Running

### Prerequisites
- Node.js 20+
- Docker & Docker Compose (for containerized deployment)

### Local Development
1. Install dependencies:
   ```bash
   npm install
   ```
2. Configure environment:
   - Create a `.env` file based on `.env.example` or use the `setup.sh` script.
3. Start the server:
   ```bash
   npm run dev
   ```
   The application will be available at `http://localhost:8000` by default.

### Docker Deployment
1. Run the setup script to prepare directories and permissions:
   ```bash
   ./setup.sh
   ```
2. Start the containers:
   ```bash
   docker compose up -d
   ```

## Development Conventions

- **State Management:** Backend state is stored in SQLite (`data/app.db`). Frontend state is managed via vanilla JS and API calls.
- **File Uploads:** Files are stored in `uploads/chat/`. Security checks (MIME/extension) are implemented in `server.js`.
- **Configuration:** Use `.env` for all environment-specific settings (ports, secrets, admin credentials).
- **API Style:** RESTful JSON endpoints primarily located within `server.js`.
- **Styling:** Vanilla CSS with a focus on "app-like" mobile responsiveness.

## Key Files
- `server.js`: Main backend logic, API routes, and database schema definition.
- `index.html`: Main dashboard frontend.
- `login.html`: Authentication interface.
- `setup.sh`: Automated environment setup and deployment script.
- `regelboken.json`: (If present) Initial data for the Rule Book.
- `Dockerfile` / `docker-compose.yml`: Containerization configuration.
