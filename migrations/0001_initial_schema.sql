-- Initial SQLite database schema for dtnpm-mod-rego-routing

CREATE TABLE IF NOT EXISTS rego_blacklist (
    id TEXT PRIMARY KEY,
    eid_pattern TEXT NOT NULL UNIQUE,
    reason TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    created_by TEXT NOT NULL DEFAULT 'system'
);

CREATE INDEX IF NOT EXISTS idx_rego_blacklist_enabled ON rego_blacklist(enabled);
CREATE INDEX IF NOT EXISTS idx_rego_blacklist_created_at ON rego_blacklist(created_at DESC);

CREATE TABLE IF NOT EXISTS rego_policy_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    active_profile TEXT NOT NULL DEFAULT 'default',
    hop_limit INTEGER NOT NULL DEFAULT 16,
    treb_block_type INTEGER NOT NULL DEFAULT 201,
    custom_ingress_rego TEXT,
    custom_egress_rego TEXT,
    custom_routing_rego TEXT,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL DEFAULT 'system'
);
