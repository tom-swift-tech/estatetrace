# Evidence field catalog

Paths are relative to a resource observation view:

| Field path | Meaning | Provider |
| --- | --- | --- |
| `tags.<name>` | Resource tag value | Azure |
| `location` | Azure region | Azure |
| `type` | Resource type | Azure |
| `resourceGroup` | Resource group name | Azure |
| `name` | Resource name | Azure |
| `properties.*` | Provider-specific properties projected into inventory | Azure |

Operators: `exists`, `nonempty`, `equals`, `not_equals`, `in`, `not_in`.
