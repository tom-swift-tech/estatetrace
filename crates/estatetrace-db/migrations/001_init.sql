PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    needs_sign_in INTEGER NOT NULL DEFAULT 0,
    last_refresh TEXT,
    access_issue TEXT
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    state TEXT NOT NULL,
    quota_id TEXT,
    tags_json TEXT NOT NULL DEFAULT '{}',
    access_issue TEXT,
    last_refresh TEXT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE TABLE IF NOT EXISTS scope_decisions (
    id TEXT PRIMARY KEY NOT NULL,
    provider TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    subscription_id TEXT,
    decision TEXT NOT NULL,
    source TEXT NOT NULL,
    matching_rule_id TEXT,
    reason TEXT,
    effective_from TEXT NOT NULL,
    effective_to TEXT
);

CREATE TABLE IF NOT EXISTS exclusion_rules (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    tenant_id TEXT,
    filter_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_defaults (
    tenant_id TEXT PRIMARY KEY NOT NULL,
    auto_track_new INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY NOT NULL,
    source TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    completeness TEXT NOT NULL,
    error TEXT
);

CREATE TABLE IF NOT EXISTS source_coverage (
    id TEXT PRIMARY KEY NOT NULL,
    source TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    last_success TEXT,
    last_checkpoint TEXT,
    gap_start TEXT,
    gap_end TEXT,
    notes TEXT,
    UNIQUE(source, subscription_id)
);

CREATE TABLE IF NOT EXISTS resource_observations (
    id TEXT PRIMARY KEY NOT NULL,
    provider TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    name TEXT NOT NULL,
    location TEXT,
    resource_group TEXT,
    tags_json TEXT NOT NULL,
    properties_json TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    observation_time TEXT NOT NULL,
    evidence_available INTEGER NOT NULL DEFAULT 1,
    lifecycle_epoch INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_obs_resource ON resource_observations(resource_id, observation_time);
CREATE INDEX IF NOT EXISTS idx_obs_sub ON resource_observations(subscription_id);

CREATE TABLE IF NOT EXISTS change_events (
    id TEXT PRIMARY KEY NOT NULL,
    resource_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    source_event_id TEXT,
    label TEXT NOT NULL,
    event_time TEXT,
    observation_time TEXT NOT NULL,
    before_json TEXT,
    after_json TEXT,
    property_diffs_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(source_event_id)
);

CREATE INDEX IF NOT EXISTS idx_change_resource ON change_events(resource_id, observation_time);

CREATE TABLE IF NOT EXISTS latest_resources (
    resource_id TEXT PRIMARY KEY NOT NULL,
    observation_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    missing INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS classification_rules (
    id TEXT PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL,
    subscription_id TEXT,
    resource_group TEXT,
    tag_key TEXT,
    tag_value TEXT,
    environment TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS policy_packs (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    revision TEXT NOT NULL,
    owner TEXT,
    activated INTEGER NOT NULL DEFAULT 0,
    reviewed_by TEXT,
    content_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(id, revision)
);

CREATE TABLE IF NOT EXISTS evaluations (
    id TEXT PRIMARY KEY NOT NULL,
    observation_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    control_revision TEXT NOT NULL,
    outcome TEXT NOT NULL,
    severity TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    evaluated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_eval_resource ON evaluations(resource_id, evaluated_at);

CREATE TABLE IF NOT EXISTS exceptions (
    id TEXT PRIMARY KEY NOT NULL,
    resource_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    reason TEXT,
    approved_by TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dispositions (
    id TEXT PRIMARY KEY NOT NULL,
    evaluation_id TEXT NOT NULL,
    owner TEXT,
    disposition TEXT NOT NULL,
    ticket_ref TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS export_artifacts (
    id TEXT PRIMARY KEY NOT NULL,
    pack_id TEXT NOT NULL,
    pack_revision TEXT NOT NULL,
    control_id TEXT NOT NULL,
    state TEXT NOT NULL,
    target_scope_json TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    bicep_text TEXT,
    mapping_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS ticket_relationships (
    id TEXT PRIMARY KEY NOT NULL,
    resource_id TEXT,
    change_id TEXT,
    owning_service TEXT,
    instance_url TEXT NOT NULL,
    record_id TEXT NOT NULL,
    record_number TEXT,
    relationship_type TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    lookup_status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incident_change_lookups (
    id TEXT PRIMARY KEY NOT NULL,
    incident_id TEXT NOT NULL,
    anchor_time TEXT,
    anchor_source TEXT,
    lookback_hours INTEGER NOT NULL,
    matched_json TEXT NOT NULL,
    coverage_json TEXT NOT NULL,
    query_scope_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS saved_views (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    filter_json TEXT NOT NULL,
    group_by TEXT,
    sort_by TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS connector_status (
    name TEXT PRIMARY KEY NOT NULL,
    configured INTEGER NOT NULL DEFAULT 0,
    last_test_ok INTEGER,
    last_test_at TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS sn_queue_cache (
    queue_name TEXT NOT NULL,
    record_id TEXT NOT NULL,
    instance_url TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    refresh_instant TEXT NOT NULL,
    PRIMARY KEY (queue_name, instance_url, record_id)
);

CREATE TABLE IF NOT EXISTS sn_queue_meta (
    queue_name TEXT PRIMARY KEY NOT NULL,
    last_success TEXT,
    last_refresh TEXT,
    stale INTEGER NOT NULL DEFAULT 0,
    unavailable INTEGER NOT NULL DEFAULT 0,
    error TEXT
);