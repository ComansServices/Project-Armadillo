# Project Armadillo v3 — Option A Architecture (TypeScript-first)

## Stack
- **Frontend:** Next.js (App Router) + Tailwind + Cytoscape/ECharts
- **API:** NestJS (Fastify adapter) + OpenAPI
- **Workers:** BullMQ + Redis
- **DB:** PostgreSQL + Prisma
- **Auth:** OIDC/SAML via Auth0 or Keycloak (RBAC + MFA)
- **Infra:** Docker + Terraform + managed Postgres/Redis
- **Observability:** OpenTelemetry + Prometheus/Grafana + Sentry

## System Diagram

```mermaid
flowchart LR
  U[User / Analyst] --> W[Next.js Web App]
  W -->|JWT/OIDC| A[NestJS API]
  W -->|SSE/WebSocket status| A

  A --> P[(PostgreSQL)]
  A --> R[(Redis)]
  A --> Q[BullMQ Queue]

  Q --> K[Scan Worker Pool]
  K --> N[Nmap Engine Container]
  N --> X[Raw XML Artifacts]
  K --> P

  A --> C[CVE/Enrichment Service]
  C --> E[External Feeds / NVD / CPE]
  C --> P

  A --> O[OTel Collector]
  K --> O
  W --> O
  O --> G[Grafana/Prometheus]
  O --> S[Sentry]
```

## Runtime Boundaries
- **Web app:** UI only, no direct scanner execution.
- **API:** AuthZ, tenancy, CRUD, orchestration, reporting endpoints.
- **Worker:** Executes scans/import parsing with constrained capability profile.
- **Scanner container:** Runs `nmap` under restricted network/file policies.

## Security Baseline
- No debug mode in prod, strict CORS/CSRF policies.
- Secrets from runtime secret manager (no repo secrets).
- RBAC by org/project/asset group.
- Immutable audit log for scan launches, edits, exports.
- Signed job payloads and worker allowlist execution profiles.

## Core Domain Objects
- `users`, `orgs`, `projects`
- `scan_jobs`, `scan_runs`, `scan_artifacts`
- `hosts`, `services`, `ports`, `cpe`, `cve_findings`
- `labels`, `notes`, `diff_reports`, `pdf_reports`
- `api_clients`, `audit_events`
