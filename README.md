# DevSecOps Pipeline Demo

[![CI](https://github.com/rychvalsky/devsecops-pipeline-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/rychvalsky/devsecops-pipeline-demo/actions/workflows/ci.yml)

A small **FastAPI** application ("Notes API") wrapped in a full **DevSecOps CI/CD
pipeline**. The application is deliberately tiny — it is only the thing that
flows through the pipeline. The pipeline is the point.

> Portfolio project. Work in progress — being built phase by phase.

## The pipeline

```
GitHub push / pull request
        |
        v
  CI/CD Pipeline (GitHub Actions)
        |
        +--> Lint            (ruff)
        +--> Unit / API tests (pytest + coverage)
        +--> SAST            (Bandit)          --> SARIF -> GitHub Security
        +--> Dependency scan (pip-audit)       --> report artifact
        +--> Docker build + image scan (Trivy) --> SARIF -> GitHub Security
        +--> Deploy test app (docker compose)
        |         |
        |         v
        +--> DAST (OWASP ZAP baseline)         --> ZAP report artifact
        |
        v
  Aggregated security report (one summary of every stage)
```

## The application

`Notes API` — CRUD over short text notes, backed by SQLite (no database server).

| Method | Path               | Auth          | Purpose            |
|--------|--------------------|---------------|--------------------|
| GET    | `/health`          | none          | liveness check     |
| POST   | `/notes`           | `X-API-Key`   | create a note      |
| GET    | `/notes`           | `X-API-Key`   | list notes         |
| GET    | `/notes/{note_id}` | `X-API-Key`   | fetch one note     |
| DELETE | `/notes/{note_id}` | `X-API-Key`   | delete one note    |

### Planted weaknesses (on purpose)

To prove the pipeline actually catches things, the app ships with a few
documented weaknesses, each marked in code with
`# DEMO WEAKNESS (fixed in F9): ...`. They are remediated in the final phase so
the pipeline can be seen going from red to green.

| Weakness                                   | Caught by        |
|--------------------------------------------|------------------|
| API key hard-coded in source               | Bandit (SAST)    |
| Non-constant-time key comparison           | code review      |
| Outdated dependency with a known CVE        | pip-audit        |
| Container runs as `root` (no `USER`)        | Trivy (config)   |
| Missing security response headers          | OWASP ZAP (DAST) |

## Run it locally

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux/Mac: source .venv/bin/activate

pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

Then open <http://127.0.0.1:8000/docs> for the interactive API docs.

Example request:

```bash
curl -X POST http://127.0.0.1:8000/notes \
  -H "X-API-Key: super-secret-demo-key-please-change" \
  -H "Content-Type: application/json" \
  -d '{"title": "first note", "body": "hello"}'
```

## Run the tests

```bash
pip install -r requirements-dev.txt
pytest
```

`pytest` runs the suite, measures coverage of the `app` package, and fails if
coverage drops below 95% (currently 100%). Tests use a throwaway in-memory
SQLite database per test, so they never touch `notes.db`.

## Run with Docker

```bash
docker compose up --build -d
curl http://localhost:8010/health          # -> {"status":"ok"}
docker compose down
```

The image is multi-stage (a build stage assembles a virtualenv; the runtime
stage carries only Python + that venv + `app/`), pinned to
`python:3.13-slim-bookworm`, and ships a `HEALTHCHECK`. Host port **8010** maps
to container port 8000.

## Build phases

| Phase | What it adds                                   | Status |
|-------|-----------------------------------------------|--------|
| F0    | Repo scaffold + FastAPI app                    | done   |
| F1    | pytest test suite + coverage                   | done   |
| F2    | Dockerfile + docker-compose                    | done   |
| F3    | Base CI: lint + tests                          | done   |
| F4    | SAST (Bandit)                                  | todo   |
| F5    | Dependency scan (pip-audit) + Dependabot       | todo   |
| F6    | Docker build + image scan (Trivy)             | todo   |
| F7    | Deploy test app + DAST (OWASP ZAP)             | todo   |
| F8    | Aggregated security report                     | todo   |
| F9    | Remediate planted weaknesses + polish          | todo   |

## License

MIT — see [LICENSE](LICENSE).
