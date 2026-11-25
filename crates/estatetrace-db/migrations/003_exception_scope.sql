-- P2: scoped exceptions (spec §4.5). Rebuild the table so resource_id becomes nullable and a
-- subscription or subscription + resource group scope can be stored. Existing v1 rows are
-- copied with their resource_id and null scope fields (AC-P2-4).
CREATE TABLE exceptions_new (
    id TEXT PRIMARY KEY NOT NULL,
    control_id TEXT NOT NULL,
    resource_id TEXT,
    subscription_id TEXT,
    resource_group TEXT,
    reason TEXT,
    approved_by TEXT,
    ticket_ref TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    CHECK (resource_id IS NOT NULL OR subscription_id IS NOT NULL)
);

INSERT INTO exceptions_new (id, control_id, resource_id, subscription_id, resource_group,
                            reason, approved_by, ticket_ref, expires_at, created_at)
SELECT id, control_id, resource_id, NULL, NULL, reason, approved_by, NULL, expires_at, created_at
FROM exceptions;

DROP TABLE exceptions;

ALTER TABLE exceptions_new RENAME TO exceptions;

CREATE INDEX IF NOT EXISTS idx_exceptions_control ON exceptions(control_id COLLATE NOCASE);
