# EstateTrace

Local Azure infrastructure operations dashboard (Windows MVP).

One Rust executable serves an embedded React UI on loopback, stores history in SQLite under `%LOCALAPPDATA%\EstateTrace\`, and uses the operator's Azure CLI session. ServiceNow and APIM chat are optional connectors; credentials live in Windows Credential Manager.

## Quick start

```powershell
cd ui
npm install
npm run build
cd ..
cargo run -p estatetrace -- serve --bind 127.0.0.1:8787 --open
```

CLI:

```powershell
cargo run -p estatetrace -- scan
cargo run -p estatetrace -- backup
cargo run -p estatetrace -- restore --archive path\to\backup.zip
```

## Milestones

| Milestone | Capability |
| --- | --- |
| M1 | Azure scope, inventory scans, resource timeline |
| M2 | Policy packs, production change inbox, compliance |
| M3 | Azure Policy Bicep export preview |
| M4 | Optional ServiceNow queues + BYOK chat |
| M5 | Theme, backup/restore, packaged UI |

See [INFRASTRUCTURE_OPS_DESIGN.md](INFRASTRUCTURE_OPS_DESIGN.md) for the full specification.
