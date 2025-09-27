# Swarm Scanner Backend

This FastAPI service coordinates crawl executions, manages scan results, and streams
progress updates to connected clients. It exposes REST endpoints that power the
frontend dashboard and automated scanners.

## Local Development

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

The API is available at `http://localhost:8000`. A tailored Swagger UI is served at
`http://localhost:8000/documentation` and the OpenAPI schema is exposed from
`http://localhost:8000/openapi.json`.

## Core Endpoints

| Method | Path | Description |
| ------ | ---- | ----------- |
| `GET` | `/` | Renders the custom Swagger UI for the API. |
| `GET` | `/health` | Checks database connectivity and overall service health. |
| `POST` | `/runs` | Creates a new scan run and schedules asynchronous execution. |
| `GET` | `/runs/{run_id}` | Retrieves the status and metadata for a scan run. |
| `GET` | `/runs/{run_id}/findings` | Returns all recorded findings for the scan. |
| `GET` | `/runs/{run_id}/stream` | Streams server-sent events describing scan progress. |
| `POST` | `/runs/{run_id}/findings/{finding_id}/replay` | Placeholder endpoint for replaying findings. |

### Background Jobs

The backend orchestrates crawler and scanner tasks via asynchronous workers:

- **`run_real_crawler`** fetches pages and stores artifacts per run.
- **`run_real_scanners`** analyzes crawler output and records findings.
- **`create_demo_findings`** seeds the database with sample results when no
  findings are generated.

Server-sent events (SSE) are buffered in-memory per run using the
`active_connections` dictionary. As scan stages complete, events are appended and
streamed to subscribed clients via `/runs/{run_id}/stream`.
