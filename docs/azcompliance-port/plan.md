# Plan: Port the azcompliance evaluation engine

> **Status (2026-11-25):** P0–P7 implemented and merged on `port/base`. 174 tests pass, the UI
> builds and there are no clippy errors. Task 7.4 (private parity run against the FNF catalogs)
> is operator-run and not done. Migration numbers as shipped: 002 coverage_gaps,
> 003 exception_scope, 004 classification, 005 observation_arm_meta, 006 findings. Deviations
> are recorded in the merge commits and team reports. Follow-ups:
> - drop the legacy `evaluations` table
> - add `lane` to `InboxFilter` so it becomes part of saved views
> - add an optional `title` field on `Control`
> - add a fake-collector test that drives the P5.1 drop guard through `scan.rs`

Contract: [spec.md](spec.md). Each task lists files, the spec ACs it closes, and its verification.
Run `cargo test -p <crate>` while iterating and `cargo test --workspace` at the end of each phase.
UI tasks finish with `cd ui && npm run build` and then a binary rebuild.

## Order and dependencies

```
P0 migrations ──► P1 evaluator ──► P3 intervals ──► P6 reporting
                     │                 ▲
                     └──► P2 exceptions┘ (P2 core logic is independent; its API wiring lands with P3)
P4 classification/ownership ──► (feeds P1 env applicability, P6 grouping)
P5 guards + joins (after P3, because the drop guard gates interval closing)
P7 check-map compile (after P1, independent of P3–P6)
```

Releasable checkpoints: **A = P0–P3** (trustworthy findings), **B = +P4/P5**, **C = +P6/P7**.

---

## P0: Versioned migrations (small)

| # | Task | Files | Verifies |
| --- | --- | --- | --- |
| 0.1 | Keep running `001_init.sql` every time (idempotent). Add an ordered list `[(2, include_str!("002_findings.sql")), …]`. Apply each where `meta.schema_version < n` inside one transaction, then set the version. **Done** (`MIGRATIONS` const in `estatetrace-db/src/lib.rs`). Numbers: 002 coverage_gaps (P1), 003 exception_scope (P2), 004 classification (P4), 005 observation_arm_meta (top-level ARG fields), 006 findings (P3). | `crates/estatetrace-db/src/lib.rs` | AC-P0-1, AC-P0-2 |
| 0.2 | Tests: double-migrate on a temp DB; a deliberately broken migration in a test-only list leaves the version unchanged. | `crates/estatetrace-db/tests/migrations.rs` | same |

## P1: Evaluator v2 (largest phase; contained in `estatetrace-policy` plus the kit)

| # | Task | Files | Verifies |
| --- | --- | --- | --- |
| 1.1 | Add `regex` to the workspace and the policy crate. | `Cargo.toml`, `crates/estatetrace-policy/Cargo.toml` | — |
| 1.2 | Write `kits/policy-authoring/resource_kinds.yaml` with the generic Azure kinds from azcompliance `catalogs/maps/resource_kinds.yaml`. Remove anything FNF-specific. Add `kinds.rs` with `ResourceKinds`, `resolve`, `matches` and `builtin_resource_kinds()`. | new `crates/estatetrace-policy/src/kinds.rs` | unit test that it parses; `function_app` filter test |
| 1.3 | Pack types: `Target`, `Check` (untagged), `Leaf`, `Operator`, `WhereClause`, `ContextField`, `NotEvaluated`, `GapCategory`, `ControlMode`, `Lane`, `ControlStatus`. `AppliesTo` accepts both legacy `environment` and `environments`. Keep `manual`, mapped to `not_evaluated`. | `pack.rs` | serde round-trip tests; the pilot pack still parses |
| 1.4 | `validate_pack`: check operator arguments (`order` for ordinal, `min/max`, `where`), compile every regex, resolve every `resource_kind`, require `targets` or `check` or `not_evaluated`, and return `LintIssue`s. | `pack.rs` | AC-P1-11 |
| 1.5 | Port `Test-LeafCore`, `Test-Check`, `Test-WhereItem` and `Test-ValueEqual` from `AzCompliance.Evaluate.psm1:84-288` into `evaluate_check`. Use the same detail strings, the `when_absent` suffix, `context` appending, `all_of` aggregation (fail wins over unknown, deduplicated details) and a regex cache. The existing six operators keep their current semantics (invariant 6). | `evaluator.rs` | AC-P1-4..7, AC-P1-10 |
| 1.6 | `evaluate_control`: select targets by kind or type plus kind filter plus target filter; return None if none match. Then apply environment applicability (Unknown stays in scope), then the check. Add `environment` and `detail` to `Evaluation` in core and update its constructors. | `evaluator.rs`, `estatetrace-core/src/observations.rs` | AC-P1-1, 3, 9 |
| 1.7 | `evaluate_pack`: emit one `CoverageGap` per `not_evaluated` control and per deep-only target with that type's resource count. Remove the per-resource Unknown flood for `manual`. | `evaluator.rs` | AC-P1-8 |
| 1.8 | `coverage_report` gains categories. `run_example_cases` takes an `environment` per example and returns `ExampleResult`. | `pack.rs` | AC-P1-2, 8 |
| 1.9 | Wire `scan.rs::evaluate_active_packs` to `evaluate_pack` with `env_of = classify_resource(...)` from existing rules. Persist coverage gaps (`002_coverage_gaps.sql`). Until P3 lands, keep writing `evaluations`. | `crates/estatetrace/src/scan.rs`, `repo.rs` | integration test on a fixture |
| 1.10 | `/api/compliance` adds `coverage_gaps`, `controls_evaluated` and `controls_total`. The Compliance page shows a "Not evaluated" table grouped by category. | `api.rs`, `ui/src/pages/Compliance.tsx`, `ui/src/api.ts` | AC-P1-8 |
| 1.11 | Kit: extend `policy_pack.schema.json`, `evidence_fields.md` (operators, `when_absent`, `context`, `where`, kinds list) and `PROMPT.md` (ask the AI for targets and `not_evaluated` categories). Add `examples/azure_baseline_example.yaml`: fictional IDs, about 8 generic controls (storage TLS ordinal, blob public access, HTTPS only, KV purge protection, PE count_where, NIC IP forwarding, region `in`, required tag in the hygiene lane) with pass/fail/unknown/assumed-default example cases. Add a schema-validation test (`jsonschema` dev-dependency). | `kits/policy-authoring/**`, `crates/estatetrace-policy/tests/schema.rs` | AC-P1-12 |
| 1.12 | Port azcompliance's verified knowledge as tests. For every operator/when_absent pair in the baseline example, add a fixture resource from the shape seen in Resource Graph. No real IDs. | `crates/estatetrace-policy/tests/operators.rs` | AC-P1-4 |

**Watch out:** azcompliance's `Get-EvidenceValue` treats `tags.<rest>` as one key (tag names contain dots). Make `field_value` do the same before 1.5.

## P2: Scoped exceptions (small)

| # | Task | Files | Verifies |
| --- | --- | --- | --- |
| 2.1 | Write `003_exception_scope.sql`: create `exceptions_new`, copy rows, drop the old table, rename. | `migrations/003_exception_scope.sql` | AC-P2-4 |
| 2.2 | Make `ExceptionRecord` fields optional per spec §4.5. Add `find_exception` (port of `Find-Exception`: resource ID, else subscription + optional RG, case-insensitive). | `estatetrace-core/src/findings.rs` | unit tests |
| 2.3 | Add the overlay to triage: fail + active match gives `Excepted`; fail + expired match gives `Actionable` with `exception_expired`. Pass and unknown are untouched. Add `TriageState::Excepted` to the UI status chips without changing existing colours (UI-03). | `findings.rs`, `ui/src/styles.css`, pages | AC-P2-1..3 |
| 2.4 | API `POST /api/exceptions` takes the scoped body and rejects empty scope with 400. `list_exceptions` filters by control. The finding-detail UI form gains scope selection and a ticket ref. | `api.rs`, `repo.rs`, `ui/src/pages/ResourceDetail.tsx` | AC-P2-5 |

## P3: Finding intervals (largest risk; schema plus every reader)

| # | Task | Files | Verifies |
| --- | --- | --- | --- |
| 3.1 | Write `006_findings.sql` (spec §4.4) and add the `FindingInterval`, `CloseReason`, `IntervalStats` and `FindingQuery` types. | migrations, `estatetrace-core/src/findings.rs` | — |
| 3.2 | `record_pack_evaluation`, a port of `Save-ComplianceRun`'s interval SQL (`AzCompliance.Store.psm1:157-183`). In one transaction: stage this scan's results in a temp table; close open intervals whose outcome or pack revision changed; insert new intervals; update continuing ones (detail, evidence, `last_*`). For subscriptions in `complete_subscriptions`, close open intervals with no staged row as `resource_missing` (resource not observed) or `no_longer_targeted` (resource observed but not selected). | `repo.rs` | AC-P3-1..5 |
| 3.3 | `scan.rs`: track which subscriptions finished a complete from-the-beginning pass, pass that set in, and stop calling `insert_evaluation`. | `scan.rs` | AC-P3-4, 5 |
| 3.4 | Replace `triage_evaluation`/`triage_with_history` with `triage_interval`: the deadline comes from `opened_at`, and `VerifiedCorrected` comes from an open pass interval whose predecessor for the same key closed as fail with `state_changed`. Fetch the predecessor with a query instead of scanning history. | `findings.rs`, `repo.rs` | AC-P3-2, 6 |
| 3.5 | Migrate every `list_evaluations` caller to `list_open_findings` or `findings_for_resource`. In `api.rs` these are `:393` timeline, `:473` inbox (triage per control), `:599` summary, `:1508` chat context and `:1632` evidence export. Remove the global LIMIT truncation. | `api.rs` | AC-P3-7, 8 |
| 3.6 | Pack deactivation and revision activation call `close_findings_for_pack`. | `api.rs` (`/packs`), `repo.rs` | AC-P3-9 |
| 3.7 | UI: rename `evaluations` to `findings` in `api.ts`. The timeline shows intervals as "fail since <opened_at> (rev 3)" with close reason. Show stale `last_evaluated_at` when it is older than the last scan. | `ui/src/**` | manual check plus build |
| 3.8 | Scale test: 10k × 5 × 10 scans on an in-memory SQLite DB, asserting row count and a query-time budget. | `crates/estatetrace-db/tests/intervals_scale.rs` | AC-P3-8 |
| 3.9 | Update AGENT.md (findings are intervals; never close on a partial pass) and the design doc's data-relationships "Evaluation" row. | docs | — |

**Checkpoint A:** re-run AC-02, AC-03 and AC-07 plus all P0–P3 ACs.

## P4: Environment and ownership

| # | Task | Files | Verifies |
| --- | --- | --- | --- |
| 4.1 | Collector: add a `resourcecontainers` query per subscription for RG tags. Upsert into `resource_group_tags` after the inventory batch commits. | `estatetrace-azure/src/collector.rs`, `scan.rs`, `004_classification.sql` | fixture test |
| 4.2 | Add `Dev` and `Sandbox` to `EnvironmentClass` and audit every `match`. | core, api, UI filters | compile plus tests |
| 4.3 | New rule kinds, ported from `Resolve-SubscriptionEnvironment`, `Resolve-BusinessServiceEnvironment` and `Resolve-ResourceEnvironment`, using `ClassifyInput` and `source`. Patterns use non-lookaround boundaries. Seed default rules (priorities: nonprod > prod > dev > test-family > sandbox) via a "Load suggested rules" button, never automatically. | `classification.rs`, `api.rs`, `Settings.tsx` | AC-P4-1..4 |
| 4.4 | `OwnershipConfig` in `SettingsDoc`; `derive_ownership` is a port of `Get-OwnershipValue`, the `undefined` cleanup and LOB rollup. Apply it at read time so a config change needs no rescan. | `classification.rs`, `views.rs` | AC-P4-5 |
| 4.5 | Inbox `application`/`owner` filters and `group_by`. Add a data-quality panel: counts by classification `source`, and subscriptions with no environment token (port of `run_fact` kinds `environment_source` and `no_environment_token`). | `api.rs`, `Inbox.tsx`, `Compliance.tsx` | AC-P4-6 |
| 4.6 | Private FNF settings (tag names, LOB names, business-service map) go in the operator profile's settings, documented in a private-config README. Nothing goes in `fixtures/`. | profile docs only | invariant 15 |

## P5: Collection guards and joins

| # | Task | Files | Verifies |
| --- | --- | --- | --- |
| 5.1 | `ScanGuards.resource_drop_tolerance_percent`: in `scan_subscription_paged`, when a complete pass returns fewer than `(1 - tol) × previous`, skip `mark_missing` and exclude the subscription from `complete_subscriptions`. Write a coverage note. | `scan.rs`, `views.rs` | AC-P5-1 |
| 5.2 | `JoinIndex`: build from the latest VNet observations (subnet ID → subnet object from `properties.subnets`). `resource_view` adds `join.subnet` for private endpoints and Container Apps environments. `evidence_source: join` gives unknown when absent. | `estatetrace-policy/src/joins.rs`, `scan.rs` | AC-P5-2 |

## P6: Reporting (port of `render-queries.json`)

| # | Task | Files | Verifies |
| --- | --- | --- | --- |
| 6.1 | SQL for queue, aging and flow over `finding_intervals`, scope-filtered, mirroring the `queue`, `aging` and `flow` queries in `engine/render-queries.json`. Trend comes from interval overlap with each completed scan's `started_at`. | `repo.rs` | AC-P6-2..4, 6 |
| 6.2 | Endpoints `/api/compliance/queue|aging|flow`. The default saved view uses `lane=security`; tag hygiene gets its own tab (azcompliance backlog #4). | `api.rs`, `Compliance.tsx`, `Inbox.tsx` | AC-P6-1 |
| 6.3 | `format: "readout"` evidence export: aggregates only, by control, environment, LOB name and lane, plus trend and coverage-gap categories. | `api.rs` | AC-P6-5 |

## P7: Check-map compile

| # | Task | Files | Verifies |
| --- | --- | --- | --- |
| 7.1 | `compile.rs`: port `ConvertFrom-PolicyCatalog`, `ConvertTo-PolicyTargets` and `ConvertTo-CheckLeaf` (`AzCompliance.Catalog.psm1:657-890`). Covers variants, `expected_setting` → `named_values`, `suppress`, `check_overrides` with the reason kept on the control, the every-control-accounted lint, and `verified` → `status`. | `crates/estatetrace-policy/src/compile.rs` | AC-P7-1..4 |
| 7.2 | Add `POST /api/packs/compile`. The Packs page gets a "Catalog + check map" import tab that shows lint issues, then imports. | `api.rs`, `Packs.tsx` | AC-P7-4 |
| 7.3 | Fictional fixture: `kits/policy-authoring/examples/check_map/` with a 3-control catalog and a map that uses variants. | kit | AC-P7-1..2 |
| 7.4 | Operator task, outside the repo: run the compile against the three FNF catalogs and check maps in the private profile, then compare outcome counts with azcompliance run `20261117-174227` as a parity check. Record the differences. | private | parity report |

## Validation (end of each checkpoint)

1. `cargo test --workspace`, plus `npm run build` in `ui/`.
2. The ACs listed for the phases in the checkpoint.
3. `rg -n "fnf_|FNF-AZURE|FNF-AVD" crates kits fixtures ui/src` shows no new hits.
4. Checkpoint A: a manual nonprod scan twice, confirming the interval count is stable and the inbox triage is per control.
5. After P7: the parity report against azcompliance (7.4). Explain every count difference over 1%, or fix it.

## Risks

- **P3 touches every compliance reader.** Land 3.1–3.4 behind tests first, then switch the readers in 3.5 in one PR so the API never mixes stores.
- **`Dev`/`Sandbox` enum growth** can break exhaustive matches and saved views that store `environment` strings. Handle it in 4.2 with a serde alias test.
- **The regex dialect differs from .NET.** Patterns copied from azcompliance settings that use lookarounds fail validation by design (spec invariant 16). Rewrite them with explicit boundaries.
- **Property names from memory.** azcompliance flags AZ-0004/0007/0009/0016/0018/0019 paths as least certain (`verification-status.md`). The public example pack should only use paths verified there, and should mark the rest `provisional`.
