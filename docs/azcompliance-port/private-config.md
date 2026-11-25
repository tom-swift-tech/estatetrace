# Private configuration: environment and ownership (P4, task 4.6)

Organisation-specific names never go in this repository: not in `fixtures/`, `kits/`, `crates/`
or `ui/src` (spec invariant 15). They live in the operator profile on the operator's machine,
and they reach the app through the Settings page or the profile files described below.

Everything in this file uses placeholders. Replace `<...>` with your own values in the profile,
never in a commit.

## Where the profile lives

`%LOCALAPPDATA%\EstateTrace\` (see `crates/estatetrace/src/profile.rs`):

| File | Holds | Edited through |
| --- | --- | --- |
| `settings.json` | `ownership` block: tag names, LOB roll-up pattern, LOB display names, placeholder values | Settings → Ownership tags, or by hand while the app is stopped |
| `estatetrace.db` | `classification_rules` (environment rules), `resource_group_tags` (collected) | Settings → Environment classification rules |
| `backups\*.zip` | Both of the above (`estatetrace backup`) | — |

Both files are covered by `estatetrace backup` / `restore`. Treat backups as private for the same
reason.

## Ownership tag names and LOB names (`settings.json`)

Ownership is derived when a page loads, so editing this block needs no rescan. Each value is read
from the resource's tag first, then from its resource group's tag. Tag names match
case-insensitively. Values are trimmed, and `undefined` plus anything in `placeholder_values`
counts as empty.

```json
{
  "ownership": {
    "application_tag": "<application-name-tag>",
    "application_id_tag": "<application-id-tag>",
    "owner_tag": "<owner-tag>",
    "line_of_business_tag": "<line-of-business-tag>",
    "lob_rollup_pattern": "^\\d+",
    "lob_names": {
      "<lob-id-1>": "<LOB display name 1>",
      "<lob-id-2>": "<LOB display name 2>"
    },
    "placeholder_values": ["<e.g. n/a>", "<e.g. tbd>"]
  }
}
```

- `lob_rollup_pattern` is a Rust regex. Its first match is the rolled-up ID, so `^\d+` turns
  `11.3` into `11`. The stored tag value is never changed. Saving an invalid pattern returns 400.
- `lob_names` keys are the rolled-up IDs. IDs that share a display name are reported together.
  An ID with no entry shows its raw ID.
- Leave a tag name out (or `null`) to skip that field.

## Environment rules (classification rules in the database)

Add rules in Settings → Environment classification rules. **Load suggested rules** fills in
generic defaults for review; nothing is saved until you save it. Highest priority wins. When
lower-priority rules disagree, the result is flagged `conflicting`.

Org-specific parts to fill in:

| Rule kind | Org-specific field | Example (placeholder) |
| --- | --- | --- |
| `subscription` | `subscription_id` of a known Prod subscription whose name has no token (the old "subscription override") | `<subscription-guid>` → `prod`, priority above the name patterns |
| `subscription_name_pattern` | Usually none. The suggested whole-token patterns cover `prod`, `non-prod`, `dev`, `test`/`uat`/`qa`/`stage`/`perf` and `sandbox` | Add a pattern only for an in-house naming token: `(?i)(^\|[^a-z0-9])<token>([^a-z0-9]\|$)` |
| `tag_segment` | `tag_key`: your business-service tag (values such as `<id>.<ENV>` or `<id>.<ENV>.<region>`); `segment_map`: your segment words | `tag_key: "<business-service-tag>"`, `segment_map: {"<segment-word>": "prod"}` |
| `resource_group_tag` | Same business-service tag read from the resource group (with `segment_map`), or the RG's environment tag | `tag_key: "<business-service-tag>"` |
| `tag` | Your environment tag name, if it is not `Environment` | `tag_key: "<environment-tag>"` |

The suggested `tag_segment` and `resource_group_tag` rules use the placeholder tag name
`business-service`. Change it to your tag name before saving. Patterns use Rust regex syntax
without lookarounds. A pattern that does not compile is rejected on save with 400.

Settings → Classification data quality lists tracked subscriptions whose name gives no
environment. Each one needs either a `subscription` rule or reliable tags.

## What must not be committed

- Real tag names, LOB IDs or names, subscription names or IDs, and business-service values.
- Copies of `settings.json`, `estatetrace.db` or backups.
- Test fixtures based on real data. Tests use fictional names such as `Contoso-Prod-01`,
  `Products-Shared` and tag `svc` = `1183.DEV`.
