# DevSecOps Pipeline Demo

[![CI](https://github.com/rychvalsky/devsecops-pipeline-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/rychvalsky/devsecops-pipeline-demo/actions/workflows/ci.yml)

A small **FastAPI** application ("Notes API") wrapped in a full **DevSecOps CI/CD
pipeline**: automated tests, SAST, dependency scanning, container image
scanning, and DAST, all in GitHub Actions, with findings collected into one
report. The application is deliberately tiny — it is only the thing that flows
through the pipeline. **The pipeline is the point.**

## The pipeline

Every push and pull request runs one GitHub Actions workflow with seven jobs:

```
                         ┌─────────────┐
   push / pull request ─▶│  lint (ruff)│
                         ├─────────────┴───────────────┐
                         │  test  (pytest + coverage)  │
                         ├─────────────────────────────┴──────┐
                         │  sast  (Bandit)  ── SARIF ─▶ Security tab
                         ├────────────────────────────────────┤
                         │  deps  (pip-audit)  ── run summary + artifact
                         ├────────────────────────────────────┤
                         │  build (docker build + Trivy)      │
                         │        image + Dockerfile ── SARIF ─▶ Security tab
                         ├────────────────────────────────────┤
                         │  dast  (docker compose up +        │
                         │         OWASP ZAP baseline)  ── artifact
                         └───────────────┬────────────────────┘
                                         ▼
                    report  ── merges every job's output into one
                               security-report.md (run summary + artifact)
```

Dependency findings also feed **Dependabot**, which opens update PRs on its own.

## The application

`Notes API` — CRUD over short text notes, backed by SQLite (no database server).

| Method | Path               | Auth          | Purpose            |
|--------|--------------------|---------------|--------------------|
| GET    | `/`                | none          | API root / links   |
| GET    | `/health`          | none          | liveness check     |
| POST   | `/notes`           | `X-API-Key`   | create a note      |
| GET    | `/notes`           | `X-API-Key`   | list notes         |
| GET    | `/notes/{note_id}` | `X-API-Key`   | fetch one note     |
| DELETE | `/notes/{note_id}` | `X-API-Key`   | delete one note    |

`SecurityHeadersMiddleware` adds baseline security headers to every response.
The API key is read from the `API_KEY` environment variable
(see [`.env.example`](.env.example)).

## Planted weaknesses → what caught them → the fix

The project was built with a handful of **deliberate, documented weaknesses** so
each scanner had something real to find. They were then remediated, so the
pipeline can be watched going from findings to clean.

| Weakness (early phases) | Caught by | Fix |
|---|---|---|
| API key hard-coded in source | Bandit `B105` (SAST) | read from `API_KEY` env var; non-secret dev fallback |
| Non-constant-time key comparison | code review | `hmac.compare_digest` |
| `fastapi==0.115.6` pulled a `starlette` with known CVEs | pip-audit + Trivy + Dependabot | bumped `fastapi` (→ current `starlette`) |
| Container ran as `root` | Trivy config `DS-0002` | dedicated `appuser` (uid 10001), read-only `/app` |
| Image carried pip's vendored `setuptools` / `msgpack` (flagged) | Trivy image | runtime image drops pip entirely — it isn't needed |
| No security response headers | OWASP ZAP baseline | `SecurityHeadersMiddleware` (CSP, `nosniff`, CORP, `no-store`, …) |

The `starlette` weakness was **real version drift**, not a fake package: the pin
was a few months old and the transitive dependency had picked up advisories.

### Where findings show up

| Stage | Surfaced in |
|-------|-------------|
| SAST (Bandit) | GitHub **code scanning** (Security tab), as SARIF |
| Dependencies (pip-audit) | run summary + JSON artifact; **Dependabot alerts** natively |
| Image + Dockerfile (Trivy) | code scanning, as SARIF |
| DAST (OWASP ZAP) | CI artifact — `report_html.html` / `report_md.md` / `report_json.json` |
| Everything | `report` job run summary + `security-report.md` artifact |

## Run it locally

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux/Mac: source .venv/bin/activate

pip install -r requirements-dev.txt
cp .env.example .env          # optional; sets API_KEY
uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000/docs> for the interactive API docs. Example:

```bash
curl -X POST http://127.0.0.1:8000/notes \
  -H "X-API-Key: local-dev-key-change-me" \
  -H "Content-Type: application/json" \
  -d '{"title": "first note", "body": "hello"}'
```

(`local-dev-key-change-me` is the fallback used when `API_KEY` is unset.)

## Run the tests

```bash
pip install -r requirements-dev.txt
pytest
```

`pytest` runs the suite, measures coverage of the `app` package, and fails if
coverage drops below 95% (currently 100%). Each test gets a throwaway in-memory
SQLite database, so tests never touch `notes.db`.

## Run with Docker

```bash
docker compose up --build -d
curl http://localhost:8010/health          # -> {"status":"ok"}
docker compose down
```

Multi-stage build (a build stage assembles a virtualenv; the runtime stage
carries only Python + that venv + `app/`), pinned to `python:3.13-slim-bookworm`,
runs as a non-root user, drops pip, and ships a `HEALTHCHECK`. Host port
**8010** maps to container port 8000.

## Run the scanners locally

```bash
bandit -c pyproject.toml -r app                 # SAST
pip-audit -r requirements.txt                   # dependencies
trivy config Dockerfile                         # Dockerfile misconfig
trivy image devsecops-pipeline-demo:local       # image vulnerabilities
```

`scripts/build_report.py` merges any of the SARIF / JSON outputs into one
`security-report.md` — the same script the `report` CI job runs.

## Build phases

| Phase | What it adds                                   | Status |
|-------|-----------------------------------------------|--------|
| F0    | Repo scaffold + FastAPI app                    | done   |
| F1    | pytest test suite + coverage                   | done   |
| F2    | Dockerfile + docker-compose                    | done   |
| F3    | Base CI: lint + tests                          | done   |
| F4    | SAST (Bandit)                                  | done   |
| F5    | Dependency scan (pip-audit) + Dependabot       | done   |
| F6    | Docker build + image scan (Trivy)             | done   |
| F7    | Deploy test app + DAST (OWASP ZAP)             | done   |
| F8    | Aggregated security report                     | done   |
| F9    | Remediate planted weaknesses + polish          | done   |

## License

MIT — see [LICENSE](LICENSE).
