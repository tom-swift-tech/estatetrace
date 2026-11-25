-- P4: environment classification and ownership (spec §4.6).
-- pattern: regex for subscription_name_pattern / name_token rules.
ALTER TABLE classification_rules ADD COLUMN pattern TEXT;

-- segment_map_json: JSON object segment -> environment for tag_segment (and mapped tag) rules.
ALTER TABLE classification_rules ADD COLUMN segment_map_json TEXT;

-- Resource-group tags from Resource Graph `resourcecontainers`, refreshed after each
-- successful inventory pass. Used for environment fallback and ownership at read time.
CREATE TABLE IF NOT EXISTS resource_group_tags (
    subscription_id TEXT NOT NULL,
    resource_group TEXT NOT NULL COLLATE NOCASE,
    tags_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (subscription_id, resource_group)
);
