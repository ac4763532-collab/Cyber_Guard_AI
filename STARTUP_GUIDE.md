# CyberGuard AI - Startup Guide

One-command scripts to start, check, and stop all CyberGuard AI services
in the project's required hybrid layout.

## Architecture

| Component | Where it runs | Port |
|---|---|---|
| PostgreSQL | Native Windows service (`postgresql-x64-18`) | 5432 |
| Redis | Docker container (`cyberguard-redis`) | 6379 |
| Redpanda | Docker container (`cyberguard-redpanda`) | 9092 |
| FastAPI backend | Native Windows, project virtual environment | 8000 |
| React/Vite frontend | Native Windows (`npm run dev`) | 5173 |

Only Redis and Redpanda run in Docker. The backend, frontend, and
PostgreSQL always run natively on Windows - they are never started as
Docker containers by these scripts.

## Commands

Start everything:

```powershell
.\start-cyberguard.ps1
```

Check service status:

```powershell
.\status-cyberguard.ps1
```

Stop project services:

```powershell
.\stop-cyberguard.ps1
```

## URLs

- Frontend: http://localhost:5173
- Backend API docs: http://127.0.0.1:8000/docs

## If PowerShell blocks the scripts

If your execution policy prevents running local `.ps1` files
(`cannot be loaded because running scripts is disabled on this system`),
do **not** change the machine-wide policy. Instead, bypass it for just
this one invocation:

```powershell
powershell -ExecutionPolicy Bypass -File .\start-cyberguard.ps1
```

```powershell
powershell -ExecutionPolicy Bypass -File .\status-cyberguard.ps1
```

```powershell
powershell -ExecutionPolicy Bypass -File .\stop-cyberguard.ps1
```

This only affects that single process - it does not call
`Set-ExecutionPolicy` and does not change any system or user setting.

## What each script does

### `start-cyberguard.ps1`

1. Switches to the project root.
2. Verifies Docker Desktop is running.
3. Starts the `postgresql-x64-18` Windows service if it's stopped, and
   confirms it is actually accepting connections on port 5432 (not just
   that the service shows "Running").
4. Runs `docker compose up -d redis redpanda` - only these two services -
   and waits for both containers to report `healthy` via their Docker
   healthchecks.
5. Starts the FastAPI backend in its own PowerShell window using the
   project's virtual environment (`backend\venv\Scripts\python.exe`) and
   `backend\run_windows.py`, which preserves the Selector event-loop
   configuration required by `psycopg` on Windows. If port 8000 is already
   in use, it reports the existing PID/process instead of starting a
   duplicate.
6. Waits for the backend's readiness endpoint to respond before declaring
   success.
7. Starts the Vite frontend in its own PowerShell window from `frontend\`
   using `npm run dev -- --host=127.0.0.1 --port=5173 --strictPort`. If
   port 5173 is already in use, it reports the existing PID/process
   instead of starting a duplicate.
8. Writes the backend/frontend PIDs it launched to `.cyberguard-pids.json`
   so `stop-cyberguard.ps1` can safely identify and stop only those
   processes later.
9. Prints a summary; it only reports success if every step actually
   succeeded.

### `status-cyberguard.ps1`

Read-only. Reports, for each component:

- PostgreSQL: Windows service status + TCP connectivity on 5432.
- Redis / Redpanda: Docker container health status (`docker inspect`) +
  TCP connectivity on 6379 / 9092.
- Backend: tracked process PID (if any) + live calls to
  `GET /api/v1/health` and `GET /api/v1/health/ready`.
- Frontend: tracked process PID (if any) + an HTTP check on port 5173.

### `stop-cyberguard.ps1`

- Stops only the backend/frontend processes whose PIDs were recorded by
  `start-cyberguard.ps1` in `.cyberguard-pids.json`, after confirming the
  PID still refers to a process of the expected kind. It never stops a
  process just because it happens to be using port 8000 or 5173.
- Stops (does not remove) the Redis and Redpanda containers via
  `docker compose stop redis redpanda`. Volumes and images are left
  intact.
- Never stops PostgreSQL.

## Troubleshooting

- Run `.\status-cyberguard.ps1` first to see exactly which component is
  down or degraded.
- Redis/Redpanda issues: `docker compose logs redis` / `docker compose logs redpanda`.
- Backend issues: check the backend's own PowerShell window for a Python
  traceback, or run `backend\venv\Scripts\python.exe run_windows.py`
  manually from the `backend` directory.
- Frontend issues: check the frontend's own PowerShell window, or run
  `npm run dev -- --host=127.0.0.1 --port=5173 --strictPort` manually from
  the `frontend` directory.
- "Port already in use" messages from the start script mean a previous
  instance (started by this script system or otherwise) is still running
  on that port. Use `.\status-cyberguard.ps1` to confirm what's running,
  or `.\stop-cyberguard.ps1` to stop a previously-started instance.
