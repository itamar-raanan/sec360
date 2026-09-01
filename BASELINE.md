# Engineering Baseline

Validated on 2026-09-01 using the production Docker runtimes (Python 3.12 and Node 20).

## Passing checks

- Backend: `26 passed` with `pytest -q`.
- Frontend: TypeScript and Vite production build pass.
- Frontend: ESLint passes with zero warnings.
- Frontend dependencies: `npm audit` reports zero vulnerabilities.
- Docker: backend and frontend images build successfully with locked frontend dependencies.
- Runtime: PostgreSQL is healthy; API database and scheduler health checks pass.
- Smoke tests: frontend root, Nginx API proxy, and default-admin login return HTTP 200.

## Local development

- Use Docker Compose, or Python 3.12 for the backend. The pinned database drivers do not install on the workstation's Python 3.14 runtime.
- Run backend tests in the production-matching image:

  ```bash
  docker run --rm -v "$PWD/backend:/app" -w /app sec360-backend:latest pytest -q
  ```

- Run frontend checks:

  ```bash
  cd frontend
  npm ci
  npm run lint
  npm run build
  npm audit --audit-level=low
  ```

## Remaining technical debt

- The initial Alembic migration is a placeholder. Fresh schemas currently depend on `Base.metadata.create_all()` plus runtime SQL patches; this should be replaced by a complete migration chain before formal production rollout.
- The frontend main bundle is approximately 1.04 MB minified (276 KB gzip). Route-level code splitting should be added as the UI grows.
- Backend tests emit deprecation warnings from Passlib's `crypt` integration and python-jose's use of naive UTC datetimes.
- There are no frontend unit or end-to-end tests yet; the current frontend baseline covers static linting, TypeScript, production bundling, and runtime smoke tests.
