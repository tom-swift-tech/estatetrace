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

## Alternative: catalog + check map

When the organization already keeps its policy as a structured catalog (a `catalog` header and a
`controls` list with `control_id`, `name`, `requirement_level`, `policy_statement`), do not
rewrite it as a pack. Write a **check map** beside it instead and let EstateTrace compile the two
(`POST /api/packs/compile`, or **Packs → Catalog + check map** in the UI). A worked, fictional
example with the full format and lint list is in `examples/check_map/`.

Output for this path:
1. A check map YAML (`kind: CheckMap`, `catalog_id`, `verified: false`, `checks`, `not_evaluated`)
2. A settings YAML when needed: `named_values` for approved lists, `suppress` for controls
   another catalog already asserts, `check_overrides` for operator decisions on one leaf

Rules:
- Account for every catalog control: under `checks`, or under `not_evaluated` with a category
  and a note. A control in neither list is a compile error
- Leaves use `path` and `expected` (the compile maps them to `field` and `value`); `operator`
  defaults to `equals`. A target is a `resource_kind` plus one inline leaf or `all_of`
- Use `variants` when the catalog states different levels for subsets of one resource kind (for
  example `must` on pooled host pools and `should` on personal ones). Each variant needs a
  `suffix` and a `filter`; do not also put a `filter` on its targets
- Put approved values the organization may change (regions, SKUs, access settings) in settings
  `named_values` and reference them with `expected_setting`, rather than copying them into the map
- Every `check_overrides` entry needs a `reason`; it is kept on the leaf note and the control
- Leave `verified: false`. An owner sets it to `true` after checking the bindings against real
  resources, which marks every compiled control `status: verified`
- The same rules as above apply to `when_absent`, `context`, `not_evaluated` categories, `judges`,
  `fix` and regular expressions
