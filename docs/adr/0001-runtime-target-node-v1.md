# ADR 0001: Runtime Target for v1

- Date: 2026-03-06
- Status: Accepted

## Context
- The original architecture target is ASP.NET Core + SQL Server.
- Current build environment lacks .NET SDK, while Node.js 24 is available and already running the scaffold.
- Priority is to deliver secure functional increments quickly.

## Decision
- Use the Node.js implementation as the executable v1 delivery runtime in this repository.
- Keep contracts, schema, and operational artifacts aligned with planned ASP.NET architecture boundaries.
- Revisit .NET convergence when build agents and deployment pipeline include SDK/tooling.

## Consequences
- Short-term velocity is improved for API/security/ops iterations.
- .NET parity work remains a tracked migration project, not a blocker for v1 release candidate progress.
