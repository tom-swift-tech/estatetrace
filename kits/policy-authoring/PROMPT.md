# Policy pack conversion prompt

You are converting an approved cloud policy document into an EstateTrace policy pack.

Inputs:
1. The EstateTrace JSON Schema (`policy_pack.schema.json`)
2. The evidence field catalog (`evidence_fields.md`) and the resource kinds list (`resource_kinds.yaml`)
3. The organization's policy DOCX or text

Output:
1. A YAML policy pack (`schema_version: 1`) with stable control IDs
2. A clause coverage report listing each clause as `automated_check`, `manual_evidence`, or `owner_question`
3. Example cases for pass, fail, and unknown where machine-checkable, each with a `type` so the right target selects it

Rules:
- Preserve clause location and document revision on every control
- Use only catalog fields, resource kinds from `resource_kinds.yaml`, and the operators in `evidence_fields.md`
- Give each machine-checkable control `targets`: one per resource kind the clause covers, each with a `check` (one leaf, or `all_of`). Add a `filter` when the clause covers only some resources of a kind (for example pooled host pools)
- Use `when_absent` only for a documented Azure default, so a missing property is judged instead of reported as unknown. Never use it to turn a missing value into a pass without that documentation
- Add `context` when a second value helps the owner read a failure (for example the firewall default action beside public network access)
- When no Azure property can judge a clause, write `not_evaluated: {category, note}` instead of a weak check. Pick the category: `outside_azure` (records or logs outside Azure), `more_collection` (Azure has it, EstateTrace does not collect it), `deep_collection` (needs per-resource ARM calls), `needs_decision` (the standard needs an approved list or exact value), or `by_construction` (true of every resource). The note says what evidence would be needed
- Set `lane: hygiene` for tagging and housekeeping clauses; leave security clauses on the default lane
- Leave `status` unset (provisional). An owner sets `status: verified` after checking the mapping against real resources
- Write `judges` (what the check actually judges, including what it does not) and `fix` in plain words
- Regular expressions use the Rust `regex` dialect: no lookaround and no backreferences
- Do not invent Azure write actions beyond suggested remediation metadata
- Keep quarterly restore tests and similar obligations even when Azure can only supply enrollment evidence (`not_evaluated` with `outside_azure`, or the older `manual: true`)
