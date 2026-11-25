# Infrastructure operations dashboard

**Implementation specification · Azure local MVP · 2026-11-18**

An operator opens the production change inbox, selects a newly observed resource, inspects its configuration change and policy result, and follows the evidence to a related ServiceNow ticket. Build this workflow as an open-source Rust web service on a single Windows workstation.

## Scope and delivery order

Sections 1–7 specify the local release. ServiceNow and chat must ship as optional connectors. A user can complete the inventory, compliance and Azure Policy export workflows with both disconnected. Section 8 defines acceptance tests. Section 9 describes later releases. The five pilot controls and ten-change ServiceNow exercise are proposed pilot sizes. The organization supplies the actual standards and integration settings.

| Milestone | Depends on | Working increment | Verification |
| --- | --- | --- | --- |
| M1 Local inventory | None | Launch on loopback, discover Azure scope, save exclusions, persist two scans and open a resource timeline. | AC-01, AC-02 |
| M2 Compliance inbox | M1 | Import a reviewed pack, evaluate observations, classify production and persist a filtered, grouped view. | AC-03, AC-07 |
| M3 Azure Policy export | M2 | Preview an eligible control, export Bicep and reconcile the observed assignment and resource outcome. | AC-04 |
| M4 Investigation connectors | M2 | Deliver the three ServiceNow operations queues, incident change timelines, resource-to-ticket lookup and optional chat against the same filtered data. | AC-05, AC-08, AC-09, AC-10 |
| M5 Local release | M1–M4 | Package the executable and embedded UI. Exercise theme loading, backup, restore and disconnected operation. | AC-06 and the complete local acceptance suite |

## 1. Local release contract

> The first screen after setup is a production change inbox. A row opens the resource timeline, the affected policy clause, the observed evidence and any related ServiceNow change. Every result carries its scope and collection time.

### The local Azure MVP

| Capability | Release boundary |
| --- | --- |
| Discover and track | Discover accessible tenants and subscriptions using the operator's Azure CLI session. Scan selected subscriptions, record resource versions and collect Azure change events. |
| Assess and investigate | Evaluate five pilot controls, surface coverage gaps and show new or changed resources. Save filters, grouping and ordering. Trace every finding to a clause and evidence. |
| Translate and export | Supply a reusable DOCX conversion kit for the user's approved AI. Import reviewed policy packs and export supported Azure Policy configurations as Bicep. |
| Connect and ask | Show recently executed changes, today's change schedule and ongoing high-priority incidents. Offer resource-to-ticket lookup and optional BYOK chat through the APIM-fronted Foundry model. The core dashboard works with either connector disconnected. |
| Run locally | Ship a Rust service, embedded web UI, SQLite history, Windows credential storage, a private UI theme, and a tested backup and restore path. |

### Delivery boundary

The MVP suggests configurations and produces deployment artifacts. The organization's existing deployment process assigns them. Azure then handles applicable corrections, including while the workstation is offline. Shared network access, Entra single sign-on and collection from other providers are later releases.

## 2. Azure scope and collection

### AZ-01 · Tenant and subscription selection

Refresh tenants and subscriptions visible to the signed-in Azure CLI identity. Display tenant name and ID, subscription name and ID, state, access issues and last refresh. A tenant requiring another sign-in remains visible when known. Persist the operator's choices by stable IDs. [Azure CLI account discovery](https://learn.microsoft.com/en-us/cli/azure/account)

Search across the full result set, paste subscription IDs, bulk select all matches across pages, or select a whole tenant. Offer one-time exclusion and saved rules for future subscriptions. Preview the count, sample names and match reason before saving. Filters include name, subscription tags and available quota ID. Offer suggested searches for MSDN, Visual Studio and pay-as-you-go. Let the operator verify local offer mappings before using them as exclusion rules. [Azure subscription metadata](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/list)

Within an enabled tenant, an explicit subscription choice takes precedence over a saved rule. A tenant-level choice determines whether newly discovered, unmatched subscriptions enter tracking automatically or await review. Show the effective decision on each row. Exclusion ends tracking and preserves labeled history. Apply active scope to inventory, compliance totals, ticket lookups, chat and the proposed export target.

### AZ-02 · Inventory and change collection

Run an initial baseline, manual refresh and configurable periodic scans while the service runs. Query Resource Graph per tracked scope, page results in stable resource-ID order, deduplicate, and retry throttled requests with backoff. Persist each source's checkpoint only after its batch commits. Retrying a batch must preserve unique events and findings. [Resource Graph pagination](https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/paging-results)

| Observation | Operator-facing meaning |
| --- | --- |
| New to this inventory | Baseline or newly visible resource. Label created only when there is creation evidence. Evaluate applicable controls as soon as evidence arrives. |
| Missing from a scan | Record last seen and collection scope. A partial scan, exclusion or permission change cannot establish deletion. Use explicit deletion evidence for a confirmed deletion. |
| Service offline or source unavailable | Resume with an overlapping event query and deduplicate. Show last success and unrecoverable time intervals per source and subscription. |

Azure change records cover supported control-plane changes and are queryable for 14 days. Persist them locally for longer review. A snapshot can miss changes that occurred and reversed between scans. Azure may return partial visibility under the caller's permissions. [Azure Change Analysis](https://learn.microsoft.com/en-us/azure/governance/resource-graph/changes/resource-graph-changes)  /  [Resource Graph permissions](https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview)

## 3. Dashboard and investigation

### UI-01 · Start with production changes since the last visit

Remember the operator's saved view and last visit. Bring unresolved, recurring and overdue findings to the top. Keep verified corrections available in the same view. Derive production status from configured subscription, resource group or tag mappings. Show the winning rule and flag conflicting or missing classifications. A missing tag on a resource in a known production subscription must still be visible in Prod.

| Surface | Operator actions |
| --- | --- |
| Change inbox | Filter by time, tenant, subscription, environment, resource type, application, owner, severity, compliance or ticket status. Group by subscription, owner or application. Sort by time or severity with a stable tie-breaker. |
| ServiceNow operations | On the landing dashboard, show a count and the first rows for each queue in INT-03. Open a ticket or expand an ongoing high-priority incident to inspect its pre-incident changes (INT-04). |
| Compliance dashboard | Show passing, failing, unknown and inapplicable evaluations separately. Show exceptions and pending remediation alongside the underlying results. Display counts, scope and freshness beside trend summaries. |
| Resource detail | Inspect property-level before and after values, provider event time, observation time, resource owner and repository when supplied. Open the source clause, evaluation evidence and ticket detail from the same timeline. |
| Finding detail | Record an owner, disposition, ticket reference or approved exception with expiry. Preserve finding history when an exception expires or a previously resolved violation recurs. |
| Evidence export | Export the selected finding or change with resource identity, timestamps, coverage, clause revision, observed values, and permitted ticket references. Include filter scope when exporting a view. |

### UI-02 · Explain what is still in progress

For controls with asynchronous fixes, show the expected grace period and last check. A new vault can show “awaiting diagnostics” while Azure configures logging. After the deadline, an uncorrected resource enters the action queue. Show “verified corrected” only after fresh evidence satisfies the check.

### UI-03 · Company UI theme

Ship a neutral theme and an optional private theme.yaml for logo, header, sidebar, canvas and accent colors. Preview it on a real table row, navigation selection and button. Preserve traditional compliance status colors, icons and labels. The company can update the dashboard's appearance independently of product releases.

## 4. Policy authoring and evaluation

### POL-01 · A portable authoring kit

Ship a versioned JSON Schema, YAML and JSON examples, an evidence-field catalog, a synthetic DOCX and a reusable prompt or skill. The user gives the kit and a policy document to an AI tool approved for that document. The tool returns a draft pack and a clause coverage report. Uploading a policy document to the dashboard's optional chat is a separate choice.

Require a stable control ID, owner, clause location and revision, effective date, applicability, severity, evidence requirements, and expected result. Each provider mapping declares the fields it can supply. Use a limited set of typed operators such as existence, equality and set membership. The evaluator runs the reviewed checks deterministically against stored observations.

### POL-02 · Example of a draft control

```yaml
schema_version: 1
id: FIN-014
source: {document: "Cloud Standard", revision: "3", clause: "4.2"}
owner: "Cloud Finance"
effective_from: "2026-12-01"
severity: medium
applies_to: {environment: prod, capability: supports_tags}
check: {field: tags.CostCenter, operator: nonempty}
azure_remediation: {effect: modify, when: absent, inherit_from: resource_group}
```

Example intent: a production resource needs a cost-center tag. The approved correction supplies a missing value only when its parent has an authoritative value. An empty tag fails this example check and requires review. An unreadable tag collection returns unknown. Preserve an existing value unless the clause authorizes replacement.

### POL-03 · Review and publish a pack

Validate syntax, field names and operators. Show the mapping from every clause to automated checks, manual evidence or questions for the owner. Preserve requirements such as quarterly restore tests even when Azure can only supply backup-enrollment evidence. Require an owner-reviewed revision and passing example cases before activation. Evaluate later pack revisions separately so a policy edit cannot masquerade as a resource change.

Pilot five controls from the organization's own standards. Suggested fixtures cover a required tag, an inherited tag, a permitted region, a diagnostic destination and an evidence requirement needing human review. Published examples use fictional policies.

## 5. Azure Policy recommendations and export

### EXP-01 · Suggest a correction for each eligible clause

Prefer an existing Azure built-in when its condition and effect satisfy the approved wording. Otherwise use a reviewed custom template from the supported catalog. Surface unsupported clauses and missing parameters. When an existing Azure Policy evaluation supplies the evidence, retain its assignment ID, result and timestamp. [Azure Policy compliance data](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/get-compliance-data)

| Preferred behavior | Example and review criteria |
| --- | --- |
| Correct during creation or update | Use modify for a missing tag when the parent supplies the approved value. Check property and API-version support. For alias conflicts, default to audit so an unsupported modification can be skipped and surfaced. [Modify effect](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-modify) |
| Correct after a successful deployment | Use deployIfNotExists for supported diagnostic settings. Verify required categories and workspace ID in the existence condition. Show the evaluation delay, identity, permissions and expected cost. [DeployIfNotExists effect](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-deploy-if-not-exists) |
| Observe or request review | Use audit or manual review when the correct value is unknown, a change could disrupt service, or the control requires human evidence. A policy owner must explicitly choose a blocking deny effect. |

### EXP-02 · Preview and export

Show the control revision, existing visible assignments, intended scope and exclusions, matching inventory count and examples, proposed change, required inputs, identity and least-privilege roles. Flag an apparent overlap with an inherited assignment and identify any uninspected scope. A preview estimates impact using the latest inventory.

Export Bicep with built-in references or custom definitions, an initiative, assignment parameters, identity and role assignments. Include the control-to-definition mapping, exception scopes and rollout notes. Keep future creates and updates separate from a selectable remediation task for existing resources. Explain how to stop future corrections and what restoring prior values would require. [Azure remediation tasks](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources)

### EXP-03 · Verify the outcome

Record suggested, exported, assigned and verified states with timestamps and evidence. Compare observed assignments to the exported revision. Show the rollout ticket and application deployment ticket separately when both are known. A successful deployment still needs fresh resource evidence to mark the finding resolved.

## 6. Optional integrations

### INT-01 · ServiceNow change lookup

Accept an HTTPS instance URL and service-account username and password. “Test and save” checks access to the configured configuration-item and change records. Store the credential in Windows Credential Manager under the operator's account. Allow test, replacement and disconnect. Store only the connection reference and test status in SQLite. [Windows credential access](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreadw)

Configure the lookup from tenant and Azure resource ID to a ServiceNow configuration item, then to primary or affected items and change requests. Support an owning application or service when tickets are recorded at that level. Show number, summary, state, change window and record link. Read permitted details on demand. Identify evidence for an explicit relationship, a candidate based on timing, and an operator-confirmed match. Distinguish zero matches from an unavailable or unauthorized lookup. [ServiceNow Change Management API](https://www.servicenow.com/docs/r/api-reference/rest-apis/change-management-api.html)

> Pilot the mapping against ten known production changes. Record how many can be linked exactly, how many require a human decision, and which fields are missing. Use this result to set expectations for the inbox.

### INT-02 · Ask about this view

The first bring-your-own-key (BYOK) connector targets a Microsoft Foundry model behind Azure API Management (APIM). Configure the gateway HTTPS chat route, model or deployment name, optional API version, key and header name. Default the header to Ocp-Apim-Subscription-Key. Store the key in the local credential store and test with a synthetic prompt. The Rust service makes the request. [Azure OpenAI through APIM](https://learn.microsoft.com/en-us/azure/api-management/azure-openai-api-from-specification)

Use bounded, read-only dashboard queries for counts, resource history, findings and ticket references. Enforce scope in the service for every request. Treat ticket text and resource metadata as data. The model can request approved lookups and cannot run arbitrary SQL, change cloud resources or deploy a policy. Apply the current view filters and show the matching records, evidence time and gaps with the answer.

Send the question and the minimum approved result fields to the configured gateway. Default to resource metadata, compliance evidence, ticket numbers and states. Make ticket descriptions and work notes opt-in. Keep credentials outside prompts and logs. If the gateway is unavailable, preserve the view and its data.

### INT-03 · ServiceNow operations queues

Query ServiceNow change requests and incidents directly so the operator can see operational activity before Azure collection discovers a related resource change. Use one refresh instant for all three queues. Store timestamps in UTC and display them in the configured operations time zone, initially the workstation's zone. Display the zone beside today's date.

| Queue | Membership | Ordering and row details |
| --- | --- | --- |
| Changes executed in the last 48 hours | A CHG has a recorded actual implementation end in the rolling interval from 48 hours ago through the refresh instant, inclusive. Include successful, unsuccessful and backed-out implementations when execution is recorded. Planned, updated and ticket-closure timestamps alone do not establish execution. | Most recent actual end first. Show actual end and implementation outcome when supplied. |
| Changes scheduled today | A CHG's planned start falls between local midnight inclusive and the next local midnight exclusive. Show the full day's schedule, including changes that have started or finished. Exclude canceled schedules. A CHG completed today may legitimately appear in both change queues. | Planned start ascending. Show the planned window and current state so an operator can distinguish upcoming, in-progress and completed work. |
| Ongoing high-priority incidents | An INC currently has a configured high priority (default P1 or P2) and an ongoing lifecycle state. Include qualifying incidents regardless of age. Exclude resolved, closed and canceled states. A reopened incident reappears if its current priority qualifies. | Highest priority first, then longest open. Show priority, state and opened time. |

Each row includes ticket number, short description, assignment group, affected service or configuration item when available, and a link to ServiceNow. Open related Azure evidence when a verified association is available. Configure the ServiceNow operating scope by service or assignment group with the operator. Clearly label that scope. Within it, include tickets with no Azure mapping. Applying a tracked-resource filter narrows the view to verified, in-scope associations. Enforce the same filters on counts, drill-down and chat.

“Test and save” verifies read access to both change and incident data and validates mapped fields, priority values and lifecycle states against the instance. Refresh automatically at a configurable interval and on demand. Page results and deduplicate by instance and record ID within each queue. Report last success separately for each queue. A failed refresh labels any cached result stale, or marks the queue unavailable when no cache exists. Show zero only for a successful complete query with zero matches. [ServiceNow change planning and actual dates](https://www.servicenow.com/docs/r/it-operations-management/service-reliability-management/sr-create-change-request-form.html)

### INT-04 · Changes before an incident

From each ongoing high-priority incident, open **Changes before incident**. Anchor the search to the configured incident impact-start timestamp. When impact start is missing, use the ticket's opened time and label that fallback in the view. If both are missing, show “Incident start unavailable.” Display the anchor, its source, the operations time zone and an adjustable lookback, defaulting to 48 hours. Query relative to the incident even if it has been open for weeks.

| Match shown to the operator | Evidence required |
| --- | --- |
| Same resource | The incident and CHG share an instance-scoped configuration item ID through their primary or affected items, or both resolve to the same verified provider resource identity. |
| Same service | Both tickets explicitly reference the same service record, or their items map to that service through a configured CMDB relationship. Show the service name and the relationship used, including when the changed item differs from the incident item. |

Find CHGs with an actual implementation end at or after the beginning of the lookback and strictly before the anchor. Separately show **Implementing at incident start** when implementation began before the anchor and evidence places its end at or after the anchor, or establishes it was still executing then. A missing end alone does not establish overlap. Omit planned-only changes from both lists. Use the same ServiceNow scope and ticket permissions as INT-03 and apply any active tracked-resource filter.

Order completed changes nearest to the anchor first. Show ticket number and link, summary, actual execution times, outcome when known, elapsed time to the incident, and the shared resource or service. Show a CHG once even when it matches both ways, retaining both reasons. These matches are investigation leads. Record a causal relationship only when separately confirmed. Show “No matching changes” only when identity resolution and the lookup are complete. Identify missing mappings, partial access or stale results otherwise.

## 7. Local architecture and operations

### RUN-01 · One executable and one local database

Run the Rust web service as the signed-in Windows user with an embedded browser UI on loopback. A user-session launch and a manual scan command share the collector. Bind locally, validate browser origins and protect state-changing requests with a local session token. The Azure CLI supplies the operator's cloud session. Built-in Azure write actions belong to assigned Azure Policies deployed through the organization's own process.

| Component | Responsibility and durable records |
| --- | --- |
| Scope and collector | Resolve allowed tenant and subscription IDs. Store scope decisions, scan runs, source health, checkpoints and gap intervals. Keep raw provider IDs alongside normalized resource identities. |
| History store | SQLite records snapshots or changed property sets, provider events and both event and observation times. Timestamp scope membership and preserve earlier evidence across resource replacement or policy revision. |
| Policy engine | Load versioned packs with owner approvals and tests. Store each evaluation's control revision, resource version, evidence and outcome. Keep exception, remediation and operator decisions as separate records. |
| Integrations and UI | Serve the inbox, saved views, evidence exports and chat through the same scope-aware query layer. Store ticket references and evidence for each relationship. Resolve secret references only when calling the connector. |

### RUN-02 · Data handling and recovery

Keep private packs, theme, instance settings, inventories and tickets outside the public repository. Limit local database and backup access to the operator. Redact credentials from diagnostics. Offer retention by record type and explicit chat-history retention, with chat persistence off by default. A consistent backup includes settings, policy revisions and local history. Restore into a fresh profile and reconnect secrets separately.

### RUN-03 · Open-source and internal use

The public project includes the engine, provider interfaces, conversion kit and a demo estate with fictional policies and tickets. Confirm FNF's requirements for publishing, internal software adoption, credential use and sending approved fields to its gateway before a real pilot. Keep FNF-specific content in privately managed configuration. Select the public license after clarifying ownership and contribution terms.

### Data relationships

These are logical records. Table names and API routes are implementation choices.

| Record | Identity and required relationships |
| --- | --- |
| Scope decision | Provider, tenant and subscription IDs, effective dates, matching rule or explicit override, decision and reason. |
| Scan and coverage | Source, scope, start and finish times, completeness, last successful checkpoint and gap interval. |
| Resource observation | Provider-native resource ID, scope, scan, observation time, relevant properties and evidence availability. Preserve lifecycle boundaries when a resource ID is reused. |
| Change | Resource, source event identity when available, source event time, first observation time and available before/after evidence. |
| Evaluation (finding interval) | One interval per pack, resource and control outcome: pack revision and clause revision, outcome, severity, environment, detail and evidence, the first and latest observation and scan, `opened_at`, `last_evaluated_at`, and `closed_at` with a close reason (outcome changed, pack revision changed, control no longer applies, resource missing from a complete from-the-beginning pass, pack deactivated). At most one open interval per key; re-evaluations with the same outcome extend it. A partial or failed subscription pass never closes an interval. Grace runs from `opened_at`. Link exception, disposition and remediation state separately. |
| Ticket relationship | Resource, change or owning service, ServiceNow instance and record ID, relationship type, supporting evidence and lookup status. |
| Incident change lookup | Incident ID, anchor timestamp and source, lookback, matched CHG IDs, actual execution timestamps, relationship evidence and coverage. Bind cached results to the effective query scope. |
| Export | Pack revision, control-to-definition mapping, target scopes, parameters and artifact version. Link observed assignments and verified outcomes when evidence arrives. |

### Scope resolution

1. Start from the operator's current provider access. A configured override cannot grant access.
2. Within an enabled tenant, use an explicit subscription decision first, followed by any matching saved exclusion, then the tenant default for unmatched subscriptions.
3. Apply the resolved set before collecting resources, calculating totals, looking up tickets, answering questions or proposing policy assignment targets. Distinguish incomplete discovery from an empty scope.
4. Keep scope changes in history. Ending tracking records its effective date. A scope change alone cannot establish that a resource was created or deleted.

## 8. Acceptance tests and pilot inputs

### Build sequence

First deliver a thin end-to-end path with a tracked subscription, an excluded one, two successive inventory states and a production change inbox. Next add the five-control pilot pack, revisioned evaluations and export. Then connect ServiceNow and the APIM chat route, and verify recovery, scope enforcement and the themed UI. Both optional connectors must be testable against synthetic examples.

| Exercise | Observable acceptance result |
| --- | --- |
| AC-01 Discover and exclude | In a multi-tenant fixture, bulk-exclude hundreds of matching subscriptions. Rename a manually excluded subscription and add a new matching one. Both stay excluded. An explicit tracking override remains effective. |
| AC-02 Detect and recover | Baseline an estate, create a resource and change a setting. Interrupt a paged scan, expire access and resume. The resource timeline retains the before and after values, generates no duplicate event or false deletion, and labels uncovered intervals. |
| AC-03 Interpret a standard | Convert a DOCX with one machine-checkable clause and one manual obligation. Review the coverage report and run pass, fail and unknown examples. Revise only the pack and verify that the resulting finding identifies the policy revision. |
| AC-04 Export and verify | In a test subscription, use the normal deployment process to apply an exported assignment at the intended scope. Create a resource missing a tag. Confirm deployment succeeds, verify the corrected value and retain the evidence. Existing resources change only through an authorized action. |
| AC-05 Investigate and ask | Open a Prod row, view its configuration item and ticket, then ask the chatbot about that filtered view. Counts and linked records match the UI. Repeat with denied ticket access and an excluded subscription. The answer shows the lookup gap and respects scope. |
| AC-06 Operate offline and restore | Start with both optional connectors disconnected. Apply a company UI theme, save a grouped view, back up, and restore under a fresh profile. History, scope and the view survive. Credentials must be reconnected. |
| AC-07 Classify and triage | Remove the environment tag from a resource in a known production subscription. It stays in the Prod view. A pending asynchronous fix becomes actionable after its grace period. Fresh passing evidence resolves the finding. |
| AC-08 Protect connector data | Exercise a read-only gateway query using a synthetic record with ticket notes. Under default settings, the gateway receives allowed fields only. Saved exports, logs and backups contain neither the gateway key nor the ServiceNow password. |
| AC-09 Review operations at shift start | Freeze the clock. Include a CHG that ended exactly 48 hours ago and exclude one that ended a second earlier. A recently closed CHG with no actual end stays out. Verify both local midnight boundaries on a daylight-saving transition day. Show a completed CHG in both applicable queues. Include an older ongoing P1 and a reopened P2, exclude a resolved P1 and an ongoing P3 under the default mapping. Include an in-scope incident with no Azure link. Deny incident access and verify that changes still refresh and the incident count shows stale or unavailable. |
| AC-10 Investigate an incident | Use a P1 incident opened a week ago with recorded impact start two hours earlier than opening. Include a same-resource CHG ending exactly 48 hours before impact and a different-resource CHG on the same service ending 20 minutes before impact. Show the nearer one first and label each match. Deduplicate a CHG matching both ways. A CHG executing across impact appears in the overlap list. Omit a planned-only CHG, an unrelated CHG, an out-of-scope CHG and a CHG executed entirely between impact and ticket opening. Clear the impact start and verify the labeled opened-time fallback. Deny access to affected-item records and verify partial coverage. |

### Pilot decisions

Confirm the five corporate controls, approved source of production and ownership mappings, expected scan interval and retention. Confirm the ServiceNow operating scope, operations time zone, change execution fields, incident priorities and ongoing states. Obtain the APIM route and authentication contract. Use an authorized nonproduction scope to test exported remediation before production adoption.

## 9. Roadmap and exit criteria

### NEXT-01 · Local follow-up

Use pilot results to prioritize deeper policy conflict analysis, grouping changes by deployment or ticket, links to repositories for recurring failures, and richer evidence reports.

### HOST-01 · Hosted Azure with Entra single sign-on

Host the Rust service behind HTTPS. Give scheduled collectors scoped workload identities, durable jobs and centralized secrets. Migrate SQLite history to a shared database such as PostgreSQL. Verify counts, scope and restore results. Continue supporting local installations.

Introduce tenant-restricted Microsoft Entra ID sign-in using OpenID Connect before shared access. Map users or groups to viewer, operator and policy-administrator roles plus allowed tenant and subscription scopes. Enforce access on the server for historical records, ticket details, exports and chat evidence. Handle revoked access and log decisions. A shared connector can see more than a viewer is entitled to retrieve. [Microsoft Entra OpenID Connect](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)

> Two users with different grants must see only their own records through the UI, API, export and chat. Revocation removes access to historical evidence for that scope. Scheduled scans continue after sign-out.

### PROV-01 · Additional providers

Keep resource identity, hierarchy, observations, timestamps, capabilities, evidence and coverage in the common contract. Each adapter owns its native IDs, collection methods, evidence mappings and remediation options. A provider can report that a control needs more evidence or that export is unavailable.

| Proposed sequence | First useful increment and exit test |
| --- | --- |
| AWS | Discover authorized accounts and regions. Ingest inventory and supported change evidence. Demonstrate exclusions, resource history and one common tagging control on an approved test account. |
| Google Cloud | Discover accessible organizations, folders and projects as permissions allow. Scope inventory and changes by project. Verify equivalent policy intent using provider-specific evidence. |
| Datacenters | Choose one inventory authority with a pilot team, such as a CMDB or virtualization platform. Map site and asset IDs, reconcile duplicates and expose source freshness. Validate one common control and one manual-evidence case. |

Ship each adapter with inventory, history and compliance evidence. Add native remediation exports once the target workflow is validated.
