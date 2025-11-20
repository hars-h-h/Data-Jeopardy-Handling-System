# DataJeopardy Security Dashboard

DataJeopardy Security Dashboard is a monitoring and response dashboard focused on database-level security. It helps teams detect, classify and respond to suspicious SQL activity by combining audit logs, handler routines, per-user risk scoring, and database-level privilege management.

Tech stack: Node.js · Express · MySQL

---

## Features

- Centralized audit log viewer (recent logs + handler routine mapping)
- Per-user risk scoring with auto-lock workflows
- Handler routines (severity, automated actions, admin notifications)
- DCL management: inspect DB users, view grants, grant and revoke privileges
- Simple frontend dashboard (HTML/CSS/vanilla JS) for administration and simulation
- Extensible SQL schema with triggers, stored procedures, and helper functions

---

## Installation

### Prerequisites

- Node.js (v14+)
- MySQL Server (or MariaDB)
- npm (or yarn)

### Quick start (development)

1. Clone the repository

2. Install dependencies

```powershell
cd C:\path\to\workspace
npm install

# DataJeopardy Security Dashboard

[![Node.js CI](https://github.com/hars-h-h/Data-Jeopardy-Handling-System/actions/workflows/nodejs-ci.yml/badge.svg?branch=master)](https://github.com/hars-h-h/Data-Jeopardy-Handling-System/actions)

DataJeopardy Security Dashboard is a monitoring and response application focused on database-level security. It helps teams detect, classify, and respond to suspicious SQL activity by combining audit logs, handler routines, per-user risk scoring, and database-level privilege controls.

Tech stack: Node.js · Express · MySQL

## Features

- Centralized audit log viewer (recent logs + handler routine mapping)
- Per-user risk scoring with auto-lock workflows
- Handler routines (severity, automated actions, admin notifications)
- DCL management: inspect DB users, view grants, grant and revoke privileges
- Simple frontend dashboard (HTML/CSS/vanilla JS) for administration and simulation

## Installation

### Prerequisites

- Node.js (v14+)
- MySQL Server (or MariaDB)
- npm (or yarn)

### Quick start (development)

1. Clone the repository

2. Install dependencies

```powershell
cd C:\workspace
npm install
```

3. Create and edit environment variables

```powershell
copy .env.example .env
notepad .env
# Fill in DB_HOST, DB_USER, DB_PASS, DB_NAME, API_PORT, AUTO_LOCK_RISK_THRESHOLD
```

4. Import the database schema

```powershell
# Adjust user/host as needed; this prompts for the MySQL password
mysql -u root -p DataJeopardyDB < database\schema.sql
```

5. Start the server

```powershell
npm run dev   # uses nodemon
# or
npm start
```

The API will listen on the configured `API_PORT` (default 5000). You can verify endpoints with PowerShell:

```powershell
Invoke-RestMethod -Method Get -Uri http://localhost:5000/roles | ConvertTo-Json -Depth 5
Invoke-RestMethod -Method Get -Uri http://localhost:5000/users | ConvertTo-Json -Depth 6
Invoke-RestMethod -Method Get -Uri http://localhost:5000/logs | ConvertTo-Json -Depth 6
```

### Notes

- `.env` is ignored by Git. Do not commit real credentials.
- Replace the example SHA-256 password hashing with a secure algorithm (bcrypt or Argon2) for production.

## Architecture

Project layout:

- `database/` — SQL schema, seed data, stored procedures, triggers, and functions
- `server/` — Express application and API endpoints
- `client/` — Static dashboard UI (HTML/CSS/JS)
- `docs/` — API docs and screenshots

Runtime behavior:

- The Express API manages `Audit_Log`, `Handler_Routine`, `UserAccount`, and `Suspicious_Activity` tables.
- Database triggers automatically populate `Suspicious_Activity` for specific audit logs; stored procedures compute risk and support auto-lock workflows.
- DCL endpoints use `SHOW GRANTS`, `GRANT`, and `REVOKE`. The server DB account must have sufficient privileges to run these commands.

API Documentation

Full API reference is available at `docs/API.md`. Key endpoints include:

- `GET /users` — list application users with computed RiskScore
- `POST /add-log` — insert an audit log entry; server classifies query and assigns a handler routine
- `POST /grant-privilege` — grant a MySQL privilege to a managed DB user
- `POST /revoke-privilege` — revoke a privilege

## Contributing

Contributions are welcome — suggested workflow:

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Implement your changes and add tests where appropriate
4. Run linters/tests and ensure the project builds
5. Open a pull request with a clear description and rationale

Guidelines:

- Do not commit secrets or credentials. Use `.env` for local config.
- Keep changes small and focused.
- Update `docs/API.md` when modifying endpoints.
