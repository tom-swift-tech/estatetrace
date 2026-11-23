# Agent guide — EstateTrace

Guidance for AI agents working in this repository. Prefer this file plus the design spec over inventing architecture.

## Source of truth

1. **[INFRASTRUCTURE_OPS_DESIGN.md](INFRASTRUCTURE_OPS_DESIGN.md)** — product contract, milestones M1–M5, acceptance tests AC-01..AC-10, and out-of-scope roadmap (HOST-01, PROV-01).
2. **This file** — how to build, where code lives, and non-negotiable implementation rules.
3. **Existing code** — match current patterns before introducing new crates, frameworks, or UI systems.

Do not treat chat history or drafts as overriding the design doc unless the user explicitly changes scope.

## What this project is

Windows-local Azure operations dashboard: one Rust executable, embedded React UI on loopback, SQLite history under `%LOCALAPPDATA%\EstateTrace\`, Azure CLI for cloud identity. ServiceNow and APIM chat are **optional**; the core inbox must work with both disconnected.

Ship suggestions and Bicep artifacts. Do **not** deploy Azure Policy from this app — the org’s process assigns them.

## Layout

```
crates/estatetrace/              # binary: serve, scan, backup, restore
crates/estatetrace-core/         # domain models, scope resolution, classification
crates/estatetrace-db/           # SQLite migrations + repositories
crates/estatetrace-azure/        # Azure CLI discovery, Resource Graph collector
crates/estatetrace-policy/       # pack schema, evaluator, Bicep export helpers
crates/estatetrace-integrations/ # ServiceNow + APIM chat + Windows Credential Manager
ui/                              # React + Vite + TypeScript SPA (embedded via rust-embed)
kits/policy-authoring/           # POL-01 conversion kit (schema, examples, prompt)
fixtures/                        # synthetic multi-tenant / theme samples
```

Profile data (DB, settings, packs, themes, backups) stays on disk under the operator profile — never commit real customer packs, themes, tickets, or secrets.

## Build, run, test

```powershell
cd ui
npm install
npm run build          # writes ui/dist; required before embedding in the binary
cd ..
cargo test --workspace
cargo run -p estatetrace -- serve --bind 127.0.0.1:8787 --open
cargo run -p estatetrace -- scan
cargo run -p estatetrace -- backup
```

- Bind **loopback only** (`127.0.0.1`). CORS and `Origin` checks allow only `http://127.0.0.1` / `http://localhost`.
- Sensitive `/api` reads and all mutations require `x-session-token` from `/api/session`. Mutations also require a loopback (or absent) Origin. Only `/api/health` and `/api/session` are public.
- After UI changes, rebuild `ui/` then rebuild/run the Rust binary so `rust-embed` picks up `ui/dist`.
- Prefer targeted `cargo test -p <crate>` while iterating; run `--workspace` before claiming a milestone done.

## Non-negotiable rules

### Scope

- Resolve scope in **one** place (`estatetrace-core` / DB `resolve_effective_scope`) and reuse it for inventory, compliance totals, tickets, chat, and export targets.
- Order: provider access → explicit subscription decision → saved exclusion rule → tenant default.
- Ending tracking preserves labeled history; a scope change alone must not invent create/delete.

### Collection and evidence

- Page Resource Graph in stable resource-ID order; checkpoint only after a batch commits; retries must not duplicate events/findings.
- Persist **event time** and **observation time** (UTC). Never infer confirmed deletion from a partial scan, exclusion, or offline gap.
- Label uncovered intervals; show last success per source/subscription.

### Policy and inbox

- Evaluate packs deterministically with the limited operators in the kit. Store control **revision** on every evaluation (AC-03).
- Production classification: missing env tag on a known Prod subscription still shows in Prod (AC-07).
- “Verified corrected” only after fresh passing evidence; grace periods become actionable after the deadline.

### Connectors and secrets

- Store ServiceNow passwords and chat keys in **Windows Credential Manager** only. SQLite holds connection refs and test status — never secrets.
- Chat sends approved, scoped, read-only fields. Ticket descriptions/work notes are opt-in. Credentials never appear in prompts, logs, exports, or backups (AC-08).
- Queues and incident lookbacks follow INT-03 / INT-04 boundary rules (inclusive 48h actual end, local midnight schedule window, overlap vs completed lists).

### UI

- First real operator surface after setup is the **production change inbox**.
- Preserve compliance status colors/labels when applying `theme.yaml`.
- Keep the UI usable with connectors disconnected (AC-06).

### Product boundary

- Local MVP only unless the user asks for HOST-01 / PROV-01.
- Do not add Entra SSO, shared Postgres, multi-user hosting, or AWS/GCP adapters without an explicit request.
- Keep FNF-specific content out of the public tree; demos use fictional policies/tickets.

## Working style

- Prefer small, milestone-aligned changes that keep AC tests green.
- Extend existing crates/APIs rather than adding parallel stacks.
- When behavior is ambiguous, cite the relevant design section (e.g. AZ-02, INT-04) in the PR/commit summary.
- Do not commit `.env`, credentials, live instance URLs with embedded secrets, or operator profile databases.

## Acceptance map (quick)

| IDs | Focus |
| --- | --- |
| AC-01, AC-02 | Scope exclude/override; inventory resume without dupes/false deletes |
| AC-03, AC-07 | Pack conversion/revision; Prod classification + grace |
| AC-04 | Export Bicep; verify via org deploy + fresh resource evidence |
| AC-05, AC-08 | Scoped chat + ticket gaps; no secrets in payloads/backups |
| AC-09, AC-10 | Queue boundaries (incl. DST); changes-before-incident |
| AC-06 | Theme, backup/restore, disconnected connectors |

Fixture-backed unit/integration tests live under `crates/*/src/*_tests.rs`, `crates/*/tests/`, and `fixtures/`. Manual Azure/ServiceNow pilot steps remain operator-run against real (nonprod) instances.
