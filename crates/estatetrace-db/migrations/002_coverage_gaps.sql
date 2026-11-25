-- P1: controls (or deep-only targets) that produce no per-resource evaluations (spec §4.4).
CREATE TABLE coverage_gaps (
  pack_id TEXT NOT NULL, pack_revision TEXT NOT NULL, control_id TEXT NOT NULL,
  resource_type TEXT NOT NULL DEFAULT '', category TEXT NOT NULL, note TEXT NOT NULL,
  resource_count INTEGER NOT NULL, recorded_scan_id TEXT NOT NULL,
  PRIMARY KEY (pack_id, control_id, resource_type)
);
