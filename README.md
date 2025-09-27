# AegisFlow Monorepo Skeleton

This repository provides a sprint-ready starting point for **AegisFlow — Autonomous Web Security Optimizer**. It follows the structure outlined in the hackathon playbook and includes initial FastAPI backend scaffolding, helper services, and testing utilities.

## Layout

```
packages/
  backend/
    src/aegisflow_backend/
      main.py          # FastAPI app factory
      config.py        # environment configuration
      models.py        # SQLModel ORM models
      schemas.py       # Pydantic response/request schemas
      routes/          # REST endpoints (runs, findings, export, preview)
      services/        # detection, ranking, fix suggestions, reporting
      storage/         # database helpers
      workers/         # placeholder crawler runner
    tests/
      test_ranking.py  # sample unit test
```

## Quickstart

1. Create a virtual environment and install dependencies:

   ```bash
   cd packages/backend
   python -m venv .venv
   source .venv/bin/activate
   pip install -e .[dev]
   ```

2. Initialize the SQLite database and run the FastAPI server:

   ```bash
   python -c "from aegisflow_backend.storage.db import init_db; init_db()"
   uvicorn aegisflow_backend.main:app --reload
   ```

3. Run tests to verify the environment:

   ```bash
   pytest
   ```

The remaining packages (crawler, frontend, demo app, dev proxy) can be added following the structure documented in the sprint brief.
