# Spec: Port the azcompliance evaluation engine into EstateTrace

Source project: `C:\projects\azcompliance` (PowerShell, batch scanner). Target: this repo.
Design references: INFRASTRUCTURE_OPS_DESIGN.md §POL-01..03, UI-01..02, AZ-02, RUN-01..03, AC-02/03/07.

## 1. Problem statement

EstateTrace's policy evaluator runs every control against every resource. `applies()` in
`crates/estatetrace-policy/src/evaluator.rs` always returns true, and `scan.rs` calls it for all
observations. It supports six operators, and recorded exceptions never change a finding. Each
scan inserts one `evaluations` row per resource × control. Readers then load the newest N rows
globally, so history is truncated. Grace deadlines are measured from the newest evaluation, so
they never expire while scans run more often than the grace period. Triage also mixes controls
on the same resource.

azcompliance already solves these problems in a working engine: kind-targeted checks, a richer
operator set with Azure-default handling, scoped exception overlay, explicit coverage gaps, and
interval-based findings. We port those mechanics, not FNF's content, so EstateTrace's compliance
results are trustworthy enough to drive the production change inbox.

## 2. Non-goals

- No FNF content in the public tree: catalogs (`FNF-*`), `fnf_*` tag names, LOB names, subscription names. That material lives in the operator profile (RUN-03).
- No PowerShell, no static HTML render pipeline, no file-based `runs/` directory. EstateTrace keeps SQLite and the embedded UI.
- No selective property fetching. EstateTrace needs full `properties` for property-level diffs (UI-01 resource detail).
- No deep tier (per-resource ARM calls, such as diagnostic settings). Controls that need it are reported as coverage gaps.
- No subnet expansion into synthetic resources in this release. Joins only (Phase 5).
- No tf-factory Terraform-attribute adapters or naming-standard compiler.
- No `drift` table. azcompliance defines one but never writes it. Pack-revision interval boundaries (Phase 3) cover the policy-vs-posture split instead.
- No change to scope resolution, ServiceNow, chat transport, or Bicep export, except for reading the new findings store.
- No Azure writes of any kind.

## 3. Interfaces / contracts

### 3.1 `estatetrace-policy` (Phase 1)

```rust
// pack.rs
pub fn parse_pack_yaml(text: &str) -> Result<PolicyPack>;          // unchanged signature
pub fn parse_pack_json(text: &str) -> Result<PolicyPack>;          // unchanged signature
pub fn validate_pack(pack: &PolicyPack, kinds: &ResourceKinds) -> Result<Vec<LintIssue>>; // errors => Err
pub fn coverage_report(pack: &PolicyPack) -> CoverageReport;       // now includes not_evaluated categories
pub fn run_example_cases(pack: &PolicyPack, kinds: &ResourceKinds) -> Result<Vec<ExampleResult>>;

// kinds.rs (new)
pub fn builtin_resource_kinds() -> &'static ResourceKinds;          // include_str!("kits/policy-authoring/resource_kinds.yaml")
impl ResourceKinds {
    pub fn resolve(&self, name_or_alias: &str) -> Option<&ResourceKind>;
    pub fn matches(&self, kind: &ResourceKind, resource_view: &serde_json::Value) -> bool; // arm_type + kind filter
}

// evaluator.rs
pub struct EvalContext<'a> {
    pub environment: &'a EnvironmentClass,
    pub kinds: &'a ResourceKinds,
    pub joins: &'a JoinIndex,          // Phase 5; JoinIndex::empty() before then
}
pub fn resource_view(obs: &ResourceObservation, joins: &JoinIndex) -> serde_json::Value;
/// None when no target of the control selects this resource (type or filter mismatch).
pub fn evaluate_control(control: &Control, obs: &ResourceObservation, ctx: &EvalContext) -> Option<Evaluation>;
pub fn evaluate_check(check: &Check, view: &serde_json::Value) -> CheckResult;
pub fn evaluate_pack(
    pack: &PolicyPack,
    resources: &[ResourceObservation],
    env_of: &dyn Fn(&ResourceObservation) -> EnvironmentClass,
    kinds: &ResourceKinds,
    joins: &JoinIndex,
) -> PackEvaluation;
pub fn field_value<'a>(view: &'a Value, path: &str) -> Option<&'a Value>; // unchanged; "tags.<rest>" = one key
```

### 3.2 `estatetrace-core` (Phases 2–4)

```rust
// findings.rs
pub fn triage_interval(f: &FindingInterval, exceptions: &[ExceptionRecord], now: DateTime<Utc>) -> TriageInfo;
pub fn find_exception<'a>(exs: &'a [ExceptionRecord], f: &FindingInterval, rg: Option<&str>) -> Option<&'a ExceptionRecord>;
// triage_evaluation / triage_with_history are removed once all callers use triage_interval.

// classification.rs (Phase 4)
pub fn classify_resource(input: &ClassifyInput, rules: &[ClassificationRule]) -> ClassificationResult;
pub fn derive_ownership(input: &ClassifyInput, cfg: &OwnershipConfig) -> Ownership;
```

### 3.3 `estatetrace-db`

```rust
pub async fn migrate(pool: &SqlitePool) -> Result<()>;   // runs 001 always, then each MIGRATIONS entry once, in a transaction
pub async fn record_pack_evaluation(
    pool: &SqlitePool,
    scan_id: &str,
    pack_id: &str,
    pack_revision: &str,
    complete_subscriptions: &HashSet<SubscriptionId>,
    result: &PackEvaluation,
) -> Result<IntervalStats>;                                // one transaction
pub async fn list_open_findings(pool: &SqlitePool, q: &FindingQuery) -> Result<Vec<FindingInterval>>;
pub async fn findings_for_resource(pool: &SqlitePool, resource_id: &str) -> Result<Vec<FindingInterval>>; // open + closed
pub async fn close_findings_for_pack(pool: &SqlitePool, pack_id: &str, reason: CloseReason) -> Result<u64>;
pub async fn insert_exception(pool: &SqlitePool, ex: &ExceptionRecord) -> Result<()>;   // scoped (Phase 2)
pub async fn list_exceptions(pool: &SqlitePool, control_id: Option<&str>) -> Result<Vec<ExceptionRecord>>;
pub async fn list_coverage_gaps(pool: &SqlitePool, pack_id: Option<&str>) -> Result<Vec<CoverageGap>>;
pub async fn upsert_resource_group_tags(pool: &SqlitePool, rows: &[ResourceGroupTags]) -> Result<()>; // Phase 4
pub async fn compliance_queue(pool: &SqlitePool, q: &QueueQuery) -> Result<Vec<QueueRow>>;           // Phase 6
pub async fn compliance_aging(pool: &SqlitePool, scope: &FindingQuery) -> Result<Vec<AgingRow>>;     // Phase 6
pub async fn compliance_flow(pool: &SqlitePool, days: u32, scope: &FindingQuery) -> Result<Vec<FlowRow>>; // Phase 6
```

### 3.4 HTTP (all require `x-session-token`; mutations also need a loopback Origin)

| Method/path | Request | Response | Phase |
| --- | --- | --- | --- |
| `GET /api/findings` | query: `FindingQuery` | `{ findings: FindingInterval[], triage: TriageInfo[] }` | 3 |
| `GET /api/resources/{id}/timeline` | — | existing shape; `evaluations` replaced by `findings` (open+closed) | 3 |
| `GET /api/compliance` | — | adds `coverage_gaps`, `controls_evaluated`, `controls_total`, `excepted` | 1, 2 |
| `POST /api/exceptions` | `ExceptionCreate` (scoped) | `{ exception }` · 400 when scope is empty | 2 |
| `GET /api/compliance/queue` | `?lane=security\|hygiene&group_by=application\|owner\|subscription` | `{ rows: QueueRow[] }` | 6 |
| `GET /api/compliance/aging` | `FindingQuery` | `{ rows: AgingRow[] }` | 6 |
| `GET /api/compliance/flow` | `?days=90` | `{ rows: FlowRow[] }` | 6 |
| `POST /api/evidence/export` | adds `format: "readout"` | aggregates only, no resource IDs | 6 |
| `POST /api/packs/compile` | `{ catalog, check_map, settings? }` (YAML/JSON text) | `{ pack, issues: LintIssue[] }` · 422 on error issues | 7 |

Status codes are unchanged: 401 without a session, 403 for a bad Origin, 500 for store errors.

## 4. Data shapes

### 4.1 Pack schema (additive; `schema_version` stays 1)

```rust
pub struct Control {
    pub id: String,
    pub source: ControlSource,
    pub owner: String,
    pub effective_from: Option<String>,
    pub severity: String,
    pub applies_to: AppliesTo,                       // accepts legacy {environment: "prod"}
    #[serde(default)] pub check: Option<Check>,      // legacy: one target with resource_type "*"
    #[serde(default)] pub targets: Vec<Target>,
    #[serde(default)] pub not_evaluated: Option<NotEvaluated>,
    #[serde(default)] pub mode: ControlMode,         // scored (default) | flag
    #[serde(default)] pub lane: Lane,                // security (default) | hygiene
    #[serde(default)] pub status: ControlStatus,     // provisional (default) | verified
    pub azure_remediation: Option<AzureRemediation>,
    #[serde(default)] pub evidence_requirements: Vec<String>,
    pub grace_period_hours: Option<u64>,
    #[serde(default)] pub manual: bool,              // kept; validate maps manual=true -> not_evaluated{outside_azure}
    pub fix: Option<String>,
    pub judges: Option<String>,
}
pub struct AppliesTo { pub environments: Option<Vec<EnvironmentClass>>, pub capability: Option<String> }
pub struct Target { pub resource_kind: Option<String>, pub resource_type: Option<String>, pub filter: Option<Leaf>, pub check: Check }
#[serde(untagged)] pub enum Check { AllOf { all_of: Vec<Leaf> }, Leaf(Leaf) }
pub struct Leaf {
    pub name: Option<String>,
    pub field: String,
    pub operator: Operator,
    pub value: Option<Value>,
    pub when_absent: Option<Value>,
    pub order: Option<Vec<String>>,                  // ordinal_gte
    pub min: Option<usize>, pub max: Option<usize>,  // length_between
    #[serde(rename = "where")] pub where_: Option<WhereClause>, // count_where_*
    #[serde(default)] pub case_sensitive: bool,      // matches
    #[serde(default)] pub context: Vec<ContextField>,
    pub note: Option<String>,
    #[serde(default)] pub evidence_source: EvidenceSource, // arg (default) | join | deep
}
#[serde(rename_all = "snake_case")]
pub enum Operator { Exists, Nonempty, Equals, NotEquals, In, NotIn, Matches, LengthBetween,
                    CountEq, CountGte, CountWhereEq, CountWhereGte, OrdinalGte, Gte, Lte }
pub struct WhereClause { pub field: String, pub equals: Option<Value>, pub empty: Option<bool>, pub matches: Option<String> }
pub struct ContextField { pub label: String, pub field: String }
pub struct NotEvaluated { pub category: GapCategory, pub note: String }
#[serde(rename_all = "snake_case")]
pub enum GapCategory { OutsideAzure, MoreCollection, ByConstruction, NeedsDecision, DeepCollection }
pub struct ExampleCase { pub control_id: String, pub name: String, pub resource: Value,
                         #[serde(default)] pub environment: Option<EnvironmentClass>, pub expected: String }
```

`kits/policy-authoring/schema/policy_pack.schema.json` and `evidence_fields.md` are updated to match.

### 4.2 Resource kinds (`kits/policy-authoring/resource_kinds.yaml`, generic Azure, public)

```rust
pub struct ResourceKinds { pub kinds: BTreeMap<String, ResourceKind> }
pub struct ResourceKind { pub arm_type: String /* lowercase */, #[serde(default)] pub aliases: Vec<String>, pub filter: Option<Leaf> }
```

### 4.3 Evaluation results

```rust
pub struct CheckResult { pub outcome: EvalOutcome, pub detail: String, pub assumed_default: bool }
pub struct PackEvaluation { pub evaluations: Vec<Evaluation>, pub coverage_gaps: Vec<CoverageGap> }
pub struct CoverageGap { pub pack_id: String, pub control_id: String, pub category: GapCategory,
                         pub note: String, pub resource_type: Option<String>, pub resource_count: u64 }
// Evaluation (core) gains two fields:
pub struct Evaluation { /* existing fields */ pub environment: EnvironmentClass, pub detail: String }
// evidence JSON gains: "detail", "assumed_default", "context": {label: value}, "target_resource_type"
```

### 4.4 Findings store (`finding_intervals` in migration `005_findings.sql`; `coverage_gaps` in `002_coverage_gaps.sql`)

Migration numbers: 002 coverage_gaps (P1), 003 exception_scope (P2), 004 classification (P4), 005 findings (P3).

```sql
CREATE TABLE finding_intervals (
  id TEXT PRIMARY KEY NOT NULL,
  pack_id TEXT NOT NULL,
  pack_revision TEXT NOT NULL,
  clause_revision TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  subscription_id TEXT NOT NULL,
  control_id TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('pass','fail','unknown','inapplicable')),
  severity TEXT NOT NULL,
  environment TEXT NOT NULL,
  detail TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  opened_at TEXT NOT NULL,
  opened_scan_id TEXT NOT NULL,
  first_observation_id TEXT NOT NULL,
  last_evaluated_at TEXT NOT NULL,
  last_scan_id TEXT NOT NULL,
  last_observation_id TEXT NOT NULL,
  closed_at TEXT,
  closed_scan_id TEXT,
  close_reason TEXT CHECK (close_reason IN ('state_changed','pack_revision','no_longer_targeted','resource_missing','pack_deactivated'))
);
CREATE UNIQUE INDEX ux_finding_open ON finding_intervals(pack_id, resource_id, control_id) WHERE closed_at IS NULL;
CREATE INDEX ix_finding_resource ON finding_intervals(resource_id, opened_at);
CREATE INDEX ix_finding_control ON finding_intervals(control_id, outcome) WHERE closed_at IS NULL;

CREATE TABLE coverage_gaps (
  pack_id TEXT NOT NULL, pack_revision TEXT NOT NULL, control_id TEXT NOT NULL,
  resource_type TEXT NOT NULL DEFAULT '', category TEXT NOT NULL, note TEXT NOT NULL,
  resource_count INTEGER NOT NULL, recorded_scan_id TEXT NOT NULL,
  PRIMARY KEY (pack_id, control_id, resource_type)
);
```

```rust
pub struct FindingInterval { pub id: String, pub pack_id: String, pub pack_revision: String, pub clause_revision: String,
  pub resource_id: ResourceId, pub subscription_id: SubscriptionId, pub control_id: String, pub outcome: EvalOutcome,
  pub severity: Severity, pub environment: EnvironmentClass, pub detail: String, pub evidence: Value,
  pub opened_at: DateTime<Utc>, pub opened_scan_id: String, pub last_evaluated_at: DateTime<Utc>, pub last_scan_id: String,
  pub closed_at: Option<DateTime<Utc>>, pub close_reason: Option<CloseReason>, pub grace_period_hours: Option<u64> }
pub enum CloseReason { StateChanged, PackRevision, NoLongerTargeted, ResourceMissing, PackDeactivated }
pub struct IntervalStats { pub opened: u64, pub continued: u64, pub closed: u64 }
pub struct FindingQuery { pub subscription_id: Option<String>, pub control_id: Option<String>, pub outcome: Option<EvalOutcome>,
  pub environment: Option<String>, pub lane: Option<Lane>, pub resource_id: Option<String>, pub limit: Option<i64> }
```

### 4.5 Exceptions (migration `003_exception_scope.sql` rebuilds the table, copying rows)

```sql
CREATE TABLE exceptions (
  id TEXT PRIMARY KEY NOT NULL,
  control_id TEXT NOT NULL,
  resource_id TEXT,                -- exactly one scope shape:
  subscription_id TEXT,            --   resource_id | subscription_id | subscription_id + resource_group
  resource_group TEXT,
  reason TEXT, approved_by TEXT, ticket_ref TEXT,
  expires_at TEXT, created_at TEXT NOT NULL,
  CHECK (resource_id IS NOT NULL OR subscription_id IS NOT NULL)
);
```

```rust
pub struct ExceptionRecord { pub id: String, pub control_id: String, pub resource_id: Option<String>,
  pub subscription_id: Option<String>, pub resource_group: Option<String>, pub reason: Option<String>,
  pub approved_by: Option<String>, pub ticket_ref: Option<String>, pub expires_at: Option<DateTime<Utc>>, pub created_at: DateTime<Utc> }
pub enum TriageState { Pass, Fail, Unknown, Inapplicable, AwaitingGrace, Actionable, VerifiedCorrected, Excepted }
pub struct TriageInfo { pub state: TriageState, pub grace_deadline: Option<DateTime<Utc>>, pub grace_period_hours: Option<u64>,
  pub reason: String, pub exception_id: Option<String>, pub exception_expired: bool }
```

### 4.6 Classification and ownership (Phase 4; migration `004_classification.sql`)

```sql
ALTER TABLE classification_rules ADD COLUMN pattern TEXT;        -- subscription_name_pattern / name_token
ALTER TABLE classification_rules ADD COLUMN segment_map_json TEXT; -- tag_segment
CREATE TABLE resource_group_tags (subscription_id TEXT NOT NULL, resource_group TEXT NOT NULL COLLATE NOCASE,
  tags_json TEXT NOT NULL, observed_at TEXT NOT NULL, PRIMARY KEY (subscription_id, resource_group));
```

```rust
pub enum ClassificationRuleKind { Subscription, ResourceGroup, Tag, SubscriptionNamePattern, TagSegment, ResourceGroupTag, NameToken }
pub enum EnvironmentClass { Prod, NonProd, Dev, Sandbox, Unknown }   // Dev, Sandbox added
pub struct ClassifyInput<'a> { pub obs: &'a ResourceObservation, pub subscription_name: Option<&'a str>, pub rg_tags: Option<&'a Value> }
pub struct ClassificationResult { /* existing */ pub source: ClassificationSource }
pub enum ClassificationSource { Subscription, SubscriptionName, ResourceGroup, ResourceTag, ResourceGroupTag, TagSegment, NameToken, None }
pub struct OwnershipConfig { pub application_tag: Option<String>, pub application_id_tag: Option<String>, pub owner_tag: Option<String>,
  pub line_of_business_tag: Option<String>, pub lob_rollup_pattern: Option<String>, pub lob_names: BTreeMap<String, String>,
  #[serde(default)] pub placeholder_values: Vec<String> /* e.g. "undefined" */ }
pub struct Ownership { pub application: Option<String>, pub application_id: Option<String>, pub owner: Option<String>,
  pub line_of_business: Option<String>, pub line_of_business_name: Option<String>, pub from_resource_group: bool }
// SettingsDoc gains: pub ownership: Option<OwnershipConfig>, pub scan_guards: ScanGuards
pub struct ScanGuards { pub resource_drop_tolerance_percent: Option<u8> /* default 50 */ }
```

### 4.7 Reporting rows (Phase 6)

```rust
pub struct QueueRow { pub control_id: String, pub lane: Lane, pub group_key: String, pub environment: String,
  pub count: u64, pub subscriptions: u64, pub oldest_opened_at: DateTime<Utc>, pub new_since_last_visit: u64 }
pub struct AgingRow { pub control_id: String, pub bucket: String /* 0-7|8-30|31-90|90+ */, pub count: u64 }
pub struct FlowRow { pub day: NaiveDate, pub control_id: String, pub opened: u64, pub closed: u64 }
```

### 4.8 Check-map compile (Phase 7)

```rust
pub struct CheckMap { pub catalog_id: String, #[serde(default)] pub verified: bool,
  pub checks: BTreeMap<String, CheckBinding>, #[serde(default)] pub not_evaluated: BTreeMap<String, NotEvaluated> }
pub struct CheckBinding { pub judges: Option<String>, pub fix: Option<String>, pub targets: Vec<MapTarget>, #[serde(default)] pub variants: Vec<Variant> }
pub struct MapTarget { pub resource_kind: String, pub filter: Option<Leaf>, #[serde(flatten)] pub check: Check, pub expected_setting: Option<String> }
pub struct Variant { pub suffix: String, pub title_suffix: Option<String>, pub severity: Option<String>, pub filter: Leaf, pub note: Option<String> }
pub struct CompileSettings { #[serde(default)] pub named_values: BTreeMap<String, Value>, #[serde(default)] pub suppress: Vec<Suppression>, #[serde(default)] pub check_overrides: BTreeMap<String, Value> }
pub struct LintIssue { pub severity: LintSeverity /* error|warning */, pub control_id: Option<String>, pub message: String }
pub fn compile_check_map(catalog: &Value, map: &CheckMap, settings: &CompileSettings, kinds: &ResourceKinds) -> Result<(PolicyPack, Vec<LintIssue>)>;
```

## 5. Invariants

1. Evaluation is deterministic: the same observations, pack revision, kinds, classification rules and joins give the same outcomes and details. No clock reads inside `evaluate_*`.
2. A control evaluates a resource only when one of its targets selects the resource's type (and the kind filter and target filter pass). A legacy `check` selects all types.
3. An environment outside `applies_to.environments` gives `inapplicable`. An `Unknown` environment is always in scope.
4. A control with `not_evaluated`, or with every leaf on `evidence_source: deep`, creates no per-resource evaluations, only one `CoverageGap` per (control, target type).
5. A missing value never becomes pass. Without `when_absent`: `exists`, `matches` and `length_between` give fail; `count_*` counts 0; `nonempty` and all comparisons give unknown. With `when_absent`: evaluate the assumed value and set `assumed_default = true`.
6. The six existing operators keep their current outcomes, so `pilot_examples_pass` stays green.
7. At most one open interval per (pack_id, resource_id, control_id), enforced by the unique index.
8. An interval closes only on: an outcome change, a pack revision change, the control no longer selecting the resource, the resource missing from a *complete from-the-beginning* pass of its subscription, or pack deactivation. A partial or failed subscription scan never closes intervals for unvisited resources.
9. Grace deadline = `opened_at + grace_period_hours` of the open failing interval, never the latest re-evaluation.
10. Triage is computed per (resource, control). It never mixes controls.
11. An active exception overlays `fail` only, as `Excepted`. It never changes the stored outcome. An expired exception leaves `Actionable` with `exception_expired = true`.
12. Each finding records pack revision and clause revision (AC-03).
13. Every read (findings, queue, aging, flow, chat, export) is filtered by `resolve_effective_scope` tracked subscriptions.
14. Interval writes for one pack in one scan are a single transaction.
15. Public tree additions contain no `fnf_` tag names, `FNF-AZURE`/`FNF-AVD`/`FNF-AZURE-CONTAINER-APPS` catalog IDs, or LOB names.
16. Every regex in a pack or rule compiles at validation time. Packs with an invalid pattern are rejected, not skipped at runtime.

## 6. Acceptance criteria

Phase 0: migrations
- AC-P0-1. Given a DB at `schema_version` 1, when `migrate` runs twice, then migrations 002+ apply exactly once and `meta.schema_version` is the highest number.
- AC-P0-2. Given a migration statement that fails, then `migrate` returns Err and `schema_version` is unchanged (transaction rolled back).

Phase 1: evaluator
- AC-P1-1. Given a control targeting `storage_account` and observations of a storage account and a VM, when `evaluate_pack` runs, then exactly one evaluation is produced (the storage account).
- AC-P1-2. Given `GEO-001` with legacy `check` and the pilot pack, then `pilot_examples_pass` still passes unchanged.
- AC-P1-3. Given `applies_to.environments: [prod]`, then a NonProd resource gives `inapplicable`, a Prod resource is evaluated, and an Unknown-environment resource is evaluated.
- AC-P1-4. For each new operator there is a table test with pass, fail and missing-field rows, and the outcomes match invariant 5.
- AC-P1-5. Given `ordinal_gte` with order `[TLS1_0, TLS1_1, TLS1_2]`, expected `TLS1_2` and an absent property with `when_absent: TLS1_0`, then the outcome is fail, `assumed_default = true`, and detail ends with `(property absent; Azure default assumed)`.
- AC-P1-6. Given an `all_of` with one failing and one unknown leaf, then the outcome is fail and detail lists only the failing leaf. With one unknown and the rest passing, it is unknown.
- AC-P1-7. Given a failing leaf with `context: [{label: firewall default action, field: properties.networkAcls.defaultAction}]`, then detail contains `[firewall default action: Deny]`, or `not set` when absent.
- AC-P1-8. Given a control with `not_evaluated: {category: outside_azure}`, then zero evaluations and one coverage gap. `coverage_report` lists the category, and `/api/compliance` returns `controls_evaluated < controls_total`.
- AC-P1-9. Given a target filter `properties.hostPoolType equals Pooled`, then a Personal host pool produces no evaluation.
- AC-P1-10. Given `count_where_gte` with where `properties.privateLinkServiceConnectionState.status equals Approved` and value 1, then two Pending connections fail with detail `0 found, 1 required` and one Approved passes.
- AC-P1-11. Given a pack with `matches` value `"(?<!x)prod"` (unsupported lookbehind), then `validate_pack` returns Err naming the control.
- AC-P1-12. `policy_pack.schema.json` validates `pilot_pack.yaml` and the new `azure_baseline_example.yaml`. A JSON Schema test runs in `cargo test`.

Phase 2: exceptions
- AC-P2-1. Given an active exception scoped to subscription S + resource group R for control C, then a failing finding for C in S/R triages `Excepted` with `exception_id`, and one in S/other-RG triages `Actionable`.
- AC-P2-2. Given an exception with `expires_at` yesterday, then the finding triages `Actionable` with `exception_expired = true`.
- AC-P2-3. Given an exception on a passing finding, then the triage is `Pass` (overlay applies to fail only).
- AC-P2-4. Given an existing v1 exception row, after migration 003 it is preserved with `resource_id` set and scope fields null.
- AC-P2-5. `POST /api/exceptions` with neither `resource_id` nor `subscription_id` returns 400.

Phase 3: intervals
- AC-P3-1. Given three scans with identical failing evidence, then `finding_intervals` holds one row for that (pack, resource, control) and `last_scan_id` is the third scan.
- AC-P3-2. Given fail → pass across scans, then the fail interval closes with `state_changed`, a pass interval opens, and triage is `VerifiedCorrected`.
- AC-P3-3. Given a pack revision change with unchanged evidence, then the old interval closes with `pack_revision` and the new interval carries the new revision.
- AC-P3-4. Given a scan that fails on page 2 for subscription S, then no interval for a resource in S that was not visited is closed.
- AC-P3-5. Given a complete from-the-beginning scan in which resource X is absent, then X's open intervals close with `resource_missing`.
- AC-P3-6. (AC-07 grace) Given `grace_period_hours: 2` and a fail opened 5h ago, with re-evaluations every hour, then triage is `Actionable`. With fail opened 1h ago, it is `AwaitingGrace`.
- AC-P3-7. Given a resource failing control A and passing control B, then the inbox row reports triage per control, and B's pass does not mask A's fail.
- AC-P3-8. Given 10,000 resources × 5 controls over 10 unchanged scans, then the row count is ≤ 50,000 and `GET /api/findings?resource_id=` returns that resource's full history.
- AC-P3-9. Deactivating a pack closes its open intervals with `pack_deactivated`.

Phase 4: classification and ownership
- AC-P4-1. Rule `subscription_name_pattern` with `(^|[^a-z0-9])prod(uction)?([^a-z0-9]|$)` (case-insensitive) classifies "Corp-Prod-01" as Prod and "Products-Shared" as Unknown.
- AC-P4-2. Rule `tag_segment` on tag `svc` with map `{dev: dev, prod: prod, dr: prod}` classifies tag `1183.DEV` as Dev and `272.PROD.TX` as Prod, with `source = tag_segment`.
- AC-P4-3. With the resource Environment tag absent and RG tag `Environment=prod` present, then the result is Prod with `source = resource_group_tag`.
- AC-P4-4. AC-07 still holds: a known-Prod subscription rule beats a missing tag.
- AC-P4-5. `derive_ownership` returns the RG's application tag when the resource's is missing or `undefined`, with `from_resource_group = true`. LOB `11.3` rolls up to `11` with its configured name.
- AC-P4-6. Inbox `application` and `owner` filters and `group_by=owner|application` use `derive_ownership`.

Phase 5: collection guards and joins
- AC-P5-1. Given previous count 500 for S and a complete pass returning 10 with tolerance 50%, then no `mark_missing` or `resource_missing` closes happen, and coverage notes "resource count dropped 98%, deletions not inferred".
- AC-P5-2. Given a private endpoint whose `properties.subnet.id` names a subnet in a tracked VNet, then `join.subnet` is in the view. If the VNet is untracked, a leaf with `evidence_source: join` gives unknown with detail `joined subnet is outside the visible scope`.

Phase 6: reporting
- AC-P6-1. `/api/compliance/queue?lane=security` excludes controls with `lane: hygiene`. The default inbox view uses `lane=security`.
- AC-P6-2. Queue `new_since_last_visit` counts fail intervals with `opened_at > meta.last_visit`.
- AC-P6-3. Aging buckets for fixed `opened_at` values put exactly 7 days in `0-7` and 8 days in `8-30`.
- AC-P6-4. Flow for a day with 3 opened and 1 closed fail intervals returns `opened=3, closed=1`.
- AC-P6-5. The readout export JSON contains no string matching `/subscriptions/` (no resource IDs).
- AC-P6-6. Every reporting endpoint excludes excluded subscriptions (AC-05 scope).

Phase 7: check-map compile
- AC-P7-1. Given a fictional catalog with 3 controls, a map binding 2 and leaving the 3rd in neither list, then compile returns an error issue naming the 3rd.
- AC-P7-2. A binding with 2 variants compiles to `<id>/<suffix>` controls with their own severity and filter.
- AC-P7-3. An unknown `resource_kind` or missing `expected_setting` gives an error issue. `verified: false` gives a warning and `status: provisional` on every control.
- AC-P7-4. The compiled pack passes `validate_pack` and can be imported through `/api/packs`.
- Cross-cutting: `cargo test --workspace` green. `rg -n "fnf_|FNF-AZURE|FNF-AVD" crates kits fixtures ui/src` returns no lines added by this work.

## 7. Failure modes

| Trigger | Required behavior |
| --- | --- |
| Pack has unknown operator, unknown resource_kind, or a bad regex | `validate_pack` Err naming the control. Import returns 422. No partial activation. |
| Leaf reads a path that is not an object | Treated as missing (invariant 5). Never panics. |
| Non-numeric value for `gte`/`lte`, or a value not in `order` for `ordinal_gte` | `unknown` with detail `<field> is <v>, which is not a number` or `not a recognised value` |
| Interval write fails mid-pack | Transaction rolls back. The scan is marked `partial` with error text. The next scan re-evaluates and duplicates nothing. |
| Scan interrupted after some subscriptions | Only subscriptions with a complete from-the-beginning pass may close intervals by `resource_missing`. The rest keep their open intervals with a stale `last_evaluated_at`, shown in the UI. |
| Large unexplained resource-count drop | Deletion not inferred (AC-P5-1). Coverage labeled. |
| Migration fails | `migrate` Err. The app refuses to start with a message naming the migration. The DB is unchanged. |
| Exception with expiry in the past at creation | Accepted (backfill use), but returned with `expired: true`. It never overlays. |
| Classification rules conflict | Highest priority wins. `conflicting = true` is surfaced (existing behaviour preserved). |
| Join target outside scope | `unknown`, never `fail` (AC-P5-2). |
| Readout export requested with an empty scope | 200 with zero counts and `scope_empty: true`, distinguishing an empty scope from incomplete discovery. |
| Check-map compile with error issues | 422 with the full issue list. No pack saved. |
| `resource_kinds.yaml` fails to parse at startup | Panic in tests. At runtime the binary embeds it, so a parse failure is a build-time test failure (`builtin_resource_kinds` unit test). |

## 8. Open questions / assumptions

BLOCKING: none.

NON-BLOCKING (each is a decision you can veto):
1. The pack schema stays at `schema_version: 1` with additive optional fields, so existing packs import unchanged.
2. The legacy `evaluations` table is no longer written after Phase 3 and is not backfilled, because it has no `pack_id`. The first scan after upgrade opens fresh intervals. The table is dropped in a later migration once nothing reads it.
3. `EnvironmentClass` gains `Dev` and `Sandbox`. UI filters add them. Packs saying `prod` keep working.
4. Exceptions overlay at triage only. The stored outcome stays `fail`, per RUN-01's "keep exception … as separate records". azcompliance instead stores an EXCEPTION state.
5. A new control's default `status` is `provisional`. The pilot pack is marked `verified` explicitly so the demo is unchanged.
6. The subscription-count preflight is adapted to a per-subscription resource-count drop guard. Tenant-domain preflight is dropped because scope is already keyed by tenant ID.
7. Subnet-as-resource expansion is deferred. Only joins are ported.
8. A public `azure_baseline_example.yaml` with fictional IDs reuses generic Azure property paths and defaults learned in azcompliance (storage TLS, blob public access, Key Vault purge protection, etc.).
9. Phases 6–7 can ship after 0–3 without blocking a release.

## 9. Gate

- [x] Every section 1-8 filled (N/A entries justified)?
- [x] Every interface in §3 a concrete signature, not prose?
- [x] Every data shape in §4 a concrete type/schema, not a description?
- [x] Every acceptance criterion in §6 testable (maps to an assertion)?
- [x] Every failure mode in §7 paired with a required behavior?
- [x] §8 BLOCKING list empty?

GATE RESULT: PASS
