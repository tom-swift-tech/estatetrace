# Evidence field catalog

A check reads fields from a resource view built from the resource's Azure Resource Graph row:

| Field path | Meaning | Provider |
| --- | --- | --- |
| `id` | Resource ID | Azure |
| `subscriptionId` | Subscription ID | Azure |
| `tags.<name>` | Resource tag value. Everything after `tags.` is one key, so tag names may contain dots (`tags.app.owner`). | Azure |
| `location` | Azure region | Azure |
| `type` | Resource type, for example `Microsoft.Storage/storageAccounts` | Azure |
| `resourceGroup` | Resource group name | Azure |
| `name` | Resource name | Azure |
| `properties.*` | Provider-specific properties, as Resource Graph reports them | Azure |
| `join.<name>.*` | A related object joined to this resource (`evidence_source: join`). Not populated yet, so such leaves evaluate to unknown. | Azure |

Path segments match exactly first, then ignoring case. A path that runs through a value that is not an object is treated as missing.

## Targets and resource kinds

A control lists `targets`. Each target selects resources by `resource_kind` (a name from [`resource_kinds.yaml`](resource_kinds.yaml), such as `storage_account`, `key_vault`, `virtual_machine`, `avd_host_pool`, `container_app`) or by `resource_type` (an ARM type, or `*` for every type). An optional `filter` leaf narrows the selection; resources that fail it are not evaluated at all (for example `properties.hostPoolType equals Pooled`).

A control with the older single `check` is evaluated on every resource type.

## Checks

A target's `check` is one leaf, or `all_of: [leaf, ...]`. For `all_of`, any failing leaf makes the check fail and only the failing leaves are reported; otherwise any unknown leaf makes it unknown.

A leaf has `field`, `operator` and the operator's arguments:

| Operator | Arguments | Pass when | Missing field (no `when_absent`) |
| --- | --- | --- | --- |
| `exists` | | the field is present and not null | fail |
| `nonempty` | | the value is not blank, null or an empty list | unknown |
| `equals` | `value` | equal (strings ignore case; numbers by value) | unknown |
| `not_equals` | `value` | not equal | unknown |
| `in` | `value: [..]` | equals one of the list | unknown |
| `not_in` | `value: [..]` | equals none of the list | unknown |
| `matches` | `value: pattern`, `case_sensitive` (default false) | the regular expression matches | fail |
| `length_between` | `min`, `max` | text length within the bounds (inclusive) | fail |
| `count_eq` / `count_gte` | `value: n` | the list has exactly / at least n items | counts 0 |
| `count_where_eq` / `count_where_gte` | `value: n`, `where` | exactly / at least n list items satisfy `where` | counts 0 |
| `ordinal_gte` | `value`, `order: [weakest, ..., strongest]` | the value is at or above `value` in `order` | unknown |
| `gte` / `lte` | `value: number` | the number is at least / at most `value` | unknown |

A missing value never passes on its own.

Optional on every leaf:

- `name`: how the leaf is named in detail text (`purge protection is false; expected true`).
- `when_absent`: the value Azure applies when the property is not reported (missing or null). The leaf is judged against it, and the detail ends with `(property absent; Azure default assumed)`. Use it only for documented Azure defaults.
- `context: [{label, field}]`: values added beside a failure, for example `[firewall default action: Deny]` or `[...: not set]`.
- `note`: appended to `count_where_*` failures (`1 found, 0 allowed: data disks that are not managed disks`).
- `evidence_source`: `arg` (default), `join`, or `deep`. A target whose leaves are all `deep` needs per-resource ARM calls that are not collected; it is listed as a coverage gap instead of being evaluated.

`where` takes `field` and exactly one of `equals: value`, `empty: true|false`, or `matches: pattern` (ignores case).

Patterns use the Rust `regex` dialect. Lookaround (`(?=`, `(?!`, `(?<=`, `(?<!`) and backreferences are not supported; a pack that uses them is rejected at import. Write explicit boundaries instead, for example `(^|[^a-z0-9])prod([^a-z0-9]|$)`.

## Controls that are not evaluated per resource

Use `not_evaluated: {category, note}` when no Azure property can judge the clause:

| Category | Meaning |
| --- | --- |
| `outside_azure` | The evidence is records or logs outside Azure (access reviews, test evidence, sign-in logs) |
| `more_collection` | Azure has it, but EstateTrace does not collect it yet |
| `deep_collection` | It needs per-resource ARM calls, such as diagnostic settings |
| `needs_decision` | The standard needs an owner decision (an approved list, an exact value) first |
| `by_construction` | True of every resource, so a per-resource check says nothing |

Such controls appear under "Not evaluated" on the Compliance page and are never counted as passing. The older `manual: true` means `outside_azure`.

## Other control fields

- `applies_to.environments: [prod, nonprod, dev, sandbox]` (or the older `environment: prod`). A resource in another environment is `inapplicable`; a resource whose environment is unknown is always evaluated.
- `lane`: `security` (default) or `hygiene` (tagging and similar housekeeping).
- `mode`: `scored` (default) or `flag`.
- `status`: `provisional` (default) or `verified`, once the mapping has been checked against real evidence.
- `judges` and `fix`: what the check actually judges, and how to fix a failure, in plain words.
