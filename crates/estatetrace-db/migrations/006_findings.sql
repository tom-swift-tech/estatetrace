-- P3: findings as intervals (spec §4.4, invariants 7-14).
-- One row per (pack, resource, control) state; an open row has closed_at NULL.
-- The legacy `evaluations` table is no longer written and is not backfilled (spec §8.2).
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
-- "Observed in this scan" lookup when closing intervals (resource_missing vs no_longer_targeted).
CREATE INDEX IF NOT EXISTS ix_obs_scan_resource ON resource_observations(scan_id, resource_id);

-- Pack revisions (AC-03, AC-P3-3): 001 declared `id` as the primary key, so a second revision
-- of a pack could not be stored. Rebuild with (id, revision) as the key, copying every row.
CREATE TABLE policy_packs_new (
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    revision TEXT NOT NULL,
    owner TEXT,
    activated INTEGER NOT NULL DEFAULT 0,
    reviewed_by TEXT,
    content_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, revision)
);
INSERT INTO policy_packs_new (id, name, revision, owner, activated, reviewed_by, content_json, created_at)
  SELECT id, name, revision, owner, activated, reviewed_by, content_json, created_at FROM policy_packs;
DROP TABLE policy_packs;
ALTER TABLE policy_packs_new RENAME TO policy_packs;
