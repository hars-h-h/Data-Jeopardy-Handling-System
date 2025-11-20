# DataJeopardy Security Dashboard — API Reference

This document describes the REST API exposed by the DataJeopardy Security Dashboard server (Express + MySQL). It lists endpoints, HTTP methods, request and response formats, and example usage.

Base URL

- Default when running locally: `http://localhost:5000`
- Port and DB configuration are controlled via environment variables: `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME`, `API_PORT`, `AUTO_LOCK_RISK_THRESHOLD` (see `.env.example`).

Authentication

- The example server included with this project does not implement authentication. In production you should protect these endpoints with authentication, authorization, and transport encryption (HTTPS).

Content types

- The API accepts and returns JSON for endpoints that use request bodies. Set header: `Content-Type: application/json`.

---

## Summary of endpoints

- GET  /roles
- GET  /users
- GET  /logs
- GET  /handler-routines
- GET  /handler-stats
- POST /add-user
- POST /add-log
- POST /lock-user
- POST /unlock-user
- POST /lock-high-risk
- GET  /database-users
- GET  /user-privileges/:username
- GET  /privilege-summary
- POST /grant-privilege
- POST /revoke-privilege
- GET  /dcl-user-mapping

---

## GET /roles

Returns the list of application roles.

Request
- Method: GET
- URL: `/roles`

Response (200)

{
  "ok": true,
  "roles": [ { "RoleID": 1, "RoleName": "Admin" }, ... ]
}

Errors
- 500: { ok: false, error: "message" }

Example (curl)

curl http://localhost:5000/roles

---

## GET /users

Returns user accounts with computed risk metadata. The server may auto-lock users meeting the configured risk threshold during this call.

Request
- Method: GET
- URL: `/users`

Response (200)

{
  "ok": true,
  "users": [
    {
      "UserID": 2,
      "Username": "bob",
      "Status": "ACTIVE",
      "RoleID": 3,
      "RoleName": "User",
      "LastLogin": null,
      "FailedLoginAttempts": 0,
      "HighSeverityCount": 1,
      "RecentHighCount": 0,
      "RiskScore": 15,
      "ShouldAutoLock": false
    },
    ...
  ]
}

Notes
- `RiskScore` is a computed field derived from `Audit_Log` high-severity counts and the user's status.
- The server may perform automatic locking and insert audit entries for affected users; if that happens `/users` returns the refreshed list.

Errors
- 500: { ok: false, error: "message" }

Example

curl http://localhost:5000/users

---

## GET /logs

Returns recent audit logs joined with handler routine information.

Request
- Method: GET
- URL: `/logs`

Response (200)

{
  "ok": true,
  "logs": [
    {
      "LogID": 1,
      "UserID": 2,
      "QueryText": "SELECT * FROM UserAccount;",
      "Severity": "LOW",
      "ActionTaken": "Log query - no action needed",
      "Timestamp": "2025-11-20T12:34:56.000Z",
      "RoutineName": "Log Normal Query",
      "ThreatType": "NORMAL_QUERY"
    },
    ...
  ]
}

Example

curl http://localhost:5000/logs

---

## GET /handler-routines

Lists configured handler routines in the `Handler_Routine` table.

Request
- Method: GET
- URL: `/handler-routines`

Response (200)

{
  "ok": true,
  "routines": [
    {
      "RoutineID": 1,
      "RoutineName": "Log Normal Query",
      "ThreatType": "NORMAL_QUERY",
      "ResponseAction": "Log query - no action needed",
      "Severity": "LOW",
      "Description": "...",
      "AutoLock": 0,
      "NotifyAdmin": 0
    },
    ...
  ]
}

Example

curl http://localhost:5000/handler-routines

---

## GET /handler-stats

Returns usage counts per handler routine (joined with Audit_Log).

Request
- Method: GET
- URL: `/handler-stats`

Response (200)

{
  "ok": true,
  "stats": [
    { "RoutineID": 2, "RoutineName": "Block DROP Command", "ThreatType": "SQL_INJECTION_DROP", "Severity": "HIGH", "UsageCount": 5 },
    ...
  ]
}

Example

curl http://localhost:5000/handler-stats

---

## POST /add-user

Create a new application user.

Request
- Method: POST
- URL: `/add-user`
- Headers: `Content-Type: application/json`
- Body:

{
  "username": "alice",
  "password": "secret",
  "roleId": 3
}

Response (200)

{
  "ok": true,
  "insertedId": 11
}

Errors
- 400 for missing fields
- 500 for DB errors

Example

curl -X POST http://localhost:5000/add-user \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret","roleId":3}'

Notes
- Passwords are hashed in the server with SHA-256 (replace with a proper salted password hash in production).

---

## POST /add-log

Add a new audit log entry. The server will classify the query, map a handler routine, and store the log. Triggers may create Suspicious_Activity rows and auto-lock users depending on severity and configured rules.

Request
- Method: POST
- URL: `/add-log`
- Headers: `Content-Type: application/json`
- Body:

{
  "userId": 3,
  "query": "DROP TABLE Role;",
  "severity": "HIGH"  // optional; if omitted the handler routine's severity is used
}

Response (200)

{
  "ok": true,
  "logId": 123,
  "handlerRoutine": {
    "name": "Block DROP Command",
    "threatType": "SQL_INJECTION_DROP",
    "action": "Block and lock account immediately",
    "severity": "HIGH"
  }
}

Errors
- 400 for missing fields
- 404 if user not found
- 500 for DB/server errors

Example

curl -X POST http://localhost:5000/add-log \
  -H "Content-Type: application/json" \
  -d '{"userId":3,"query":"DROP TABLE Role;"}'

---

## POST /lock-user

Manually lock an application user (admin action simulated by the API).

Request
- Method: POST
- URL: `/lock-user`
- Headers: `Content-Type: application/json`
- Body:

{ "userId": 5 }

Response (200)

{ "ok": true }

Notes
- Inserts an `Audit_Log` entry using the `MANUAL_LOCK` routine.

Example

curl -X POST http://localhost:5000/lock-user -H "Content-Type: application/json" -d '{"userId":5}'

---

## POST /unlock-user

Manually unlock a user and reset their risk state. This endpoint deletes the user's audit logs and related `Suspicious_Activity` rows, re-activates the account, and inserts a `MANUAL_UNLOCK` audit entry.

Request
- Method: POST
- URL: `/unlock-user`
- Headers: `Content-Type: application/json`
- Body:

{ "userId": 5 }

Response (200)

{ "ok": true }

Warnings
- This action deletes audit history for the user (as implemented). In production you may prefer to mark records rather than permanently deleting them.

Example

curl -X POST http://localhost:5000/unlock-user -H "Content-Type: application/json" -d '{"userId":5}'

---

## POST /lock-high-risk

Batch-lock users whose computed risk score meets or exceeds the configured threshold. Inserts `AUTO_LOCK` audit entries for affected users.

Request
- Method: POST
- URL: `/lock-high-risk`
- Headers: `Content-Type: application/json`
- Body: `{}` (empty JSON body accepted)

Response (200)

{
  "ok": true,
  "locked": [ 4, 9 ]
}

Example

curl -X POST http://localhost:5000/lock-high-risk -H "Content-Type: application/json" -d '{}'

---

## GET /database-users

Lists MySQL users that the dashboard manages (DCL users configured in the schema): `admin_user`, `security_user`, `auditor_user`, `developer_user`, `guest_user`.

Request
- Method: GET
- URL: `/database-users`

Response (200)

{ "ok": true, "users": [ { "user": "admin_user", "host": "localhost" }, ... ] }

Note
- Requires the database account used by the server to have sufficient privileges to query `mysql.user`.

---

## GET /user-privileges/:username

Shows `SHOW GRANTS FOR 'username'@'localhost'` output parsed into JSON.

Request
- Method: GET
- URL: `/user-privileges/:username`

Path parameters
- `:username` — database username (e.g. `admin_user`)

Response (200)

{ "ok": true, "username": "admin_user", "privileges": [ { "grant": "GRANT ALL PRIVILEGES ON `DataJeopardyDB`.* TO 'admin_user'@'localhost'" } ] }

Errors
- 500 or a user-not-found message if the server DB user can't see grants for the requested account.

Example

curl http://localhost:5000/user-privileges/admin_user

---

## GET /privilege-summary

Returns a structured summary for all DCL users. The server runs `SHOW GRANTS` for each configured DCL user and extracts an array of privilege types and tables.

Request
- Method: GET
- URL: `/privilege-summary`

Response (200)

{
  "ok": true,
  "summary": [
    {
      "user": "admin_user",
      "host": "localhost",
      "privileges": ["ALL PRIVILEGES"],
      "tables": ["ALL TABLES"],
      "rawGrants": ["GRANT ALL PRIVILEGES ON `DataJeopardyDB`.* TO 'admin_user'@'localhost'"]
    },
    ...
  ]
}

Notes
- The endpoint will include an error object for users that cannot be queried.

Example

curl http://localhost:5000/privilege-summary

---

## POST /grant-privilege

Grant a privilege to one of the managed DCL database users.

Request
- Method: POST
- URL: `/grant-privilege`
- Headers: `Content-Type: application/json`
- Body:

{
  "username": "developer_user",
  "privilege": "INSERT",
  "tableName": "Handler_Routine"   // optional, use '*' or omit to grant on all tables
}

Response (200)

{ "ok": true, "message": "Granted INSERT to developer_user" }

Notes
- The server executes `GRANT ${privilege} ON \\`DB_NAME\\`.\\`table\\` TO '${username}'@'localhost'` and `FLUSH PRIVILEGES`.
- The server account must have GRANT OPTION to perform this operation.

Example

curl -X POST http://localhost:5000/grant-privilege -H "Content-Type: application/json" -d '{"username":"developer_user","privilege":"INSERT","tableName":"Handler_Routine"}'

---

## POST /revoke-privilege

Revoke a privilege from a DCL user (inverse of grant).

Request
- Method: POST
- URL: `/revoke-privilege`
- Headers: `Content-Type: application/json`
- Body:

{
  "username": "developer_user",
  "privilege": "INSERT",
  "tableName": "Handler_Routine"   // optional
}

Response (200)

{ "ok": true, "message": "Revoked INSERT from developer_user" }

Example

curl -X POST http://localhost:5000/revoke-privilege -H "Content-Type: application/json" -d '{"username":"developer_user","privilege":"INSERT","tableName":"Handler_Routine"}'

---

## GET /dcl-user-mapping

Returns a mapping of DCL users to application roles and a short description. This is a convenience endpoint used by the client to populate UI mapping data.

Request
- Method: GET
- URL: `/dcl-user-mapping`

Response (200)

{
  "ok": true,
  "mapping": [
    { "dclUser": "admin_user", "appRole": "Admin", "description": "Full database access - all operations", "privilegeLevel": "FULL" },
    ...
  ]
}

Example

curl http://localhost:5000/dcl-user-mapping

---

## Error handling notes

- Most endpoints return `{"ok": false, "error": "message"}` on server-side errors.
- Validate input before calling write endpoints (`/add-user`, `/add-log`, `/grant-privilege`, etc.).

## Security and production notes

- Never commit real credentials to source control. Use `.env` (ignored by Git) and keep `.env.example` in repository.
- Replace SHA-256 based password hashing with a proper salted algorithm such as bcrypt or Argon2.
- Protect DCL endpoints (`/grant-privilege`, `/revoke-privilege`, `/database-users`, etc.) behind strict administrative authentication and role checks.
- Consider rate-limiting and input sanitization on `/add-log` and other endpoints that accept SQL-like input.

---

If you want, I can also:
- Generate example Postman collection for these endpoints,
- Add OpenAPI (Swagger) specification to `docs/openapi.yaml` so you can auto-generate client code.

