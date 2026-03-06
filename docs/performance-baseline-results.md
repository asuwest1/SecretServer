# Performance Baseline Results

Date: 2026-03-06
Environment: local in-process API harness (`tests/perf-api.js`)

## Baseline Run

Command:

```bash
npm run test:perf:api
```

Parameters: `PERF_ITERATIONS=120`, `PERF_CONCURRENCY=12`

Results:

- authLogin: p95 50.36 ms, p99 50.36 ms, avg 43.02 ms
- secretList: p95 15.25 ms, p99 15.40 ms, avg 5.68 ms
- secretSearch: p95 6.83 ms, p99 7.05 ms, avg 4.42 ms
- secretReveal: p95 12.79 ms, p99 13.16 ms, avg 8.54 ms

## Near-Capacity Run

Command:

```bash
$env:PERF_ITERATIONS='300'; $env:PERF_CONCURRENCY='30'; npm run test:perf:api
```

Results:

- authLogin: p95 66.58 ms, p99 66.58 ms, avg 47.94 ms
- secretList: p95 26.51 ms, p99 27.67 ms, avg 10.74 ms
- secretSearch: p95 10.47 ms, p99 10.81 ms, avg 7.18 ms
- secretReveal: p95 36.78 ms, p99 37.70 ms, avg 24.52 ms

## Threshold Check

All measured p95/p99 values are below targets in `docs/performance-targets.md`.
