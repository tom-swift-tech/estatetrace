-- Top-level Resource Graph fields outside `properties` (kind, sku, identity, plan, zones,
-- managedBy, extendedLocation). Policy targets and filters read them (e.g. function apps
-- are microsoft.web/sites where kind matches functionapp).
ALTER TABLE resource_observations ADD COLUMN arm_meta_json TEXT NOT NULL DEFAULT '{}';
