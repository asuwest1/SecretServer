# Performance Qualification Targets

Workload profile for MVP qualification:

- Dataset shape: 1 folder, 1 role, 1 active operator user, at least 1 secret.
- Workflows measured: auth login, secrets list, secrets search, secret reveal.
- Test mode: local in-process API server with configurable iterations/concurrency.
- Default run parameters: `PERF_ITERATIONS=120`, `PERF_CONCURRENCY=12`.

Acceptance thresholds:

- Login: p95 <= 120 ms, p99 <= 200 ms.
- List secrets: p95 <= 90 ms, p99 <= 150 ms.
- Search secrets: p95 <= 100 ms, p99 <= 170 ms.
- Reveal secret value: p95 <= 110 ms, p99 <= 180 ms.

Execution command:

```bash
npm run test:perf:api
```
