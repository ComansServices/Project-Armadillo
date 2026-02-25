# Project Armadillo v3 — 90 Day Roadmap (Option A)

## Phase 0 (Week 1): Foundations
- Monorepo setup (pnpm + turbo)
- CI pipeline (lint/test/build)
- Base infra modules (Postgres/Redis/app)
- Auth provider decision (Auth0 vs Keycloak)

**Exit criteria:** clean CI, local dev up in one command.

## Phase 1 (Weeks 2-4): Core Platform
- NestJS API skeleton + Prisma schema v1
- Next.js shell with auth + dashboard layout
- Worker service with BullMQ connectivity
- Import pipeline: XML upload -> parse -> persist

**Exit criteria:** upload XML, view hosts/services in UI.

## Phase 2 (Weeks 5-7): Scan Execution + Observability
- Secure scan profile model (safe defaults)
- Queue-based scan launch and status tracking
- Live job status in UI (SSE/WebSocket)
- OTel traces + metrics + Sentry wiring

**Exit criteria:** launch scan from UI, monitor job lifecycle, artifacts stored.

## Phase 3 (Weeks 8-10): Security + Reporting
- RBAC policies and org/project scoping
- Audit trail endpoints and export
- PDF report generation service
- Diff report between scans

**Exit criteria:** role-restricted access + downloadable reports.

## Phase 4 (Weeks 11-13): Hardening + Beta
- Performance pass (indexes, pagination, caching)
- Integration tests for critical flows
- Threat model review + pen-test prep checklist
- Beta release + migration notes from legacy Armadillo

**Exit criteria:** production-ready beta with runbook and rollback plan.

## Risks / Controls
- **Risk:** nmap execution abuse -> **Control:** strict scan profiles + quotas + audit.
- **Risk:** queue backlog -> **Control:** bounded concurrency + autoscaling workers.
- **Risk:** noisy CVE enrichment -> **Control:** async enrichment + cache + retries.
