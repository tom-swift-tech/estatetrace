# Check-map example (fictional)

A second way to build a policy pack: instead of writing pack YAML by hand, keep the
organisation's **policy catalog** unchanged and write a **check map** beside it that binds each
catalog control to Azure evidence. EstateTrace compiles the two (plus optional **settings**)
into a normal policy pack, then you import it like any other pack.

Everything in this folder is invented: the organisation, the standard, the control IDs and
the setting values.

| File | What it is |
| --- | --- |
| `catalog.yaml` | The policy catalog: controls in prose, no rule logic |
| `check_map.yaml` | How each control is judged, or why it is not evaluated |
| `settings.yaml` | Named values, suppressions and check overrides used by the compile |

## Compile and import

In the UI: **Packs → Catalog + check map**. Paste or pick the three files, press **Compile**,
read the issue list, then **Import compiled pack** (enabled only when there are no errors).

Over HTTP (session token and loopback Origin required, like every mutation):

```
POST /api/packs/compile
{ "catalog": "<catalog text>", "check_map": "<check map text>", "settings": "<settings text>" }
→ 200 { "pack": {...}, "issues": [...] }          warnings only
→ 422 { "pack": null, "issues": [...] }           at least one error; nothing is saved
```

Then import `pack` with `POST /api/packs { "json": "<pack JSON>", "reviewed_by": ..., "activate": true }`.

In Rust: `parse_catalog`, `parse_check_map_yaml`, `parse_compile_settings` and
`compile_check_map` in `estatetrace-policy`.

## Catalog format

```yaml
catalog:
  catalog_id: EXAMPLE-WORKPLACE-CATALOG   # becomes the pack id; must match the check map
  catalog_version: "2.1"                  # becomes the pack and control revision
  title: ...                              # pack name
  authoritative_document: ...             # control source document, unless the control names one
  issuing_department: ...                 # owner (pack and controls), unless a control sets owner
controls:
  - control_id: EXW-STG-01                # control id
    name: ...                             # title; used as `judges` when the map gives none
    requirement_level: must               # must | must_<x> | should | should_<x> | may
    severity: critical                    # optional; wins over requirement_level
    policy_statement: ...
    source: [{ document: ..., section: "3.2" }]   # section becomes source.clause
    minimum_evidence: [...]               # becomes evidence_requirements
    owner: ...                            # optional
```

With no `catalog_version` (or `version`), the revision is a content hash `c-<16 hex>` of the
catalog, check map and settings together, so any change gives a new revision.

### Level and severity mapping

| Catalog value | EstateTrace severity |
| --- | --- |
| `low`, `medium`, `high`, `critical` | the same |
| `must`, `must_*` (e.g. `must_conditional`), `error` | `high` |
| `should`, `should_*`, `warning` | `medium` |
| `may` | `low` |

## Check-map format

```yaml
kind: CheckMap
catalog_id: EXAMPLE-WORKPLACE-CATALOG
verified: false            # false: warning, every control `status: provisional`; true: `verified`
checks:
  <control_id>:
    judges: ...            # what the check judges (and does not)
    fix: ...
    applies_to: { environments: [prod] }   # optional (alias applies_when)
    lane: hygiene                          # optional; security when unset
    variants:              # optional; one compiled control per variant
      - suffix: pooled     # compiled id <control_id>/pooled
        title_suffix: ...
        level: must        # or severity: high; the control's severity when unset
        filter: { path: properties.hostPoolType, expected: Pooled }
        note: ...          # appended to judges
    targets:               # one per resource kind (resource_kinds.yaml)
      - resource_kind: storage_account
        filter: { ... }    # optional; not allowed together with a variant filter
        # either one leaf, written inline:
        path: properties.minimumTlsVersion
        operator: ordinal_gte          # equals when unset
        expected: TLS1_2
        # or several:
        all_of: [ { path: ..., expected: ... }, ... ]
not_evaluated:
  <control_id>: { category: outside_azure, note: ... }
```

`category` is one of `outside_azure`, `more_collection`, `by_construction`, `needs_decision`,
`deep_collection`.

Leaf keys use the azcompliance names and map onto pack leaf fields:

| Check map | Pack leaf |
| --- | --- |
| `path` (or `field`) | `field` |
| `expected` (or `value`) | `value` |
| `expected_setting: <name>` | `value` = `settings.named_values.<name>` (a scalar is wrapped in a list for `in`/`not_in`) |
| `where: { path, equals \| empty \| matches }` | `where: { field, ... }` |
| `context: [{ label, path }]` | `context: [{ label, field }]` |
| `name`, `operator`, `when_absent`, `order`, `min`, `max`, `case_sensitive`, `note`, `evidence_source` | the same |

## Settings format

```yaml
named_values:
  approved_host_pool_access: [Disabled, EnabledForClientsOnly]
suppress:
  - { control: <control_id>, reason: ..., duplicate_of: <other id> }
check_overrides:
  <control_id or control_id/suffix>:
    leaf: minimum TLS      # leaf name or path; optional when the control has one leaf
    reason: ...            # required; kept in the leaf note and the control's judges
    expected: TLS1_1       # any leaf keys to replace
```

A suppressed control is dropped from the pack and reported as a warning with its reason.

## Lint

Errors (the compile returns 422 and nothing can be imported):

- a catalog control in neither `checks` nor `not_evaluated` (named by control id), or in both
- an unknown `resource_kind`; a leaf without `path`; a binding with no targets
- an `expected_setting` not in `named_values`
- a target filter together with a variant filter; a variant with no suffix or an unknown level
- a requirement level that is not must/should/may or a severity; duplicate or missing `control_id`
- a check map whose `catalog_id` differs from the catalog's
- a `check_overrides` entry without a reason, or whose `leaf` matches nothing
- anything `validate_pack` rejects (bad operator arguments, regex that does not compile, ...)

Warnings: `verified: false`; a suppressed control; a check map, suppress or override entry naming
a control not in the catalog; a catalog with no owner.
