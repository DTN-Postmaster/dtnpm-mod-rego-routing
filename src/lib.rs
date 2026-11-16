//! OPA/Rego declarative routing and filtering extension module for DTN Postmaster
//! and Hardy BPA (`regorus`-powered).

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, patch, post};
use dtnpm_web_core::{ModuleContext, WebModule};
use hardy_async::async_trait;
use hardy_bpa::filter::pack::FilterPack;
use rusqlite::Connection;

pub mod agent;
pub mod blocks;
pub mod engine;
pub mod error;
pub mod filter;
pub mod policy;
pub mod rib;
pub mod routes;

pub use agent::RegoRoutingAgent;
pub use engine::{
    BlacklistEntry, DecisionAuditEntry, DynamicRouteCommand, NeighborPeer, RegoRoutingConfig,
    RegoRoutingEngine,
};
pub use error::RegoRoutingError;
pub use filter::{
    REGO_BUNDLE_DECISION, RegoEgressRewriter, RegoIngressClassifier, RegoIngressVerifier,
    build_filter_pack,
};
pub use policy::{DesiredRoute, PolicySources, PolicySuite, RegoDecision, RibDecision};
pub use rib::RegoRib;

use crate::routes::RegoRouteState;

/// Initial SQLite schema executed on module registration/startup.
pub const INITIAL_SCHEMA_SQL: &str = include_str!("../migrations/0001_initial_schema.sql");

/// [`WebModule`] integrating OPA/Rego filtering, hop-count enforcement, Spray-and-Wait
/// foundations, APRS future-path trajectory rewriting, and TREB past-path tracing
/// with DTN Postmaster's WebUI and SQLite storage.
#[derive(Clone)]
pub struct RegoRoutingModule {
    engine: Arc<RegoRoutingEngine>,
    routing_agent: Arc<RegoRoutingAgent>,
}

impl std::fmt::Debug for RegoRoutingModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegoRoutingModule").finish()
    }
}

impl RegoRoutingModule {
    /// Creates a new [`RegoRoutingModule`] with default configuration and embedded Rego policies.
    pub fn new() -> anyhow::Result<Self> {
        Self::with_config(RegoRoutingConfig::default())
    }

    /// Creates a new [`RegoRoutingModule`] from an explicit [`RegoRoutingConfig`].
    pub fn with_config(config: RegoRoutingConfig) -> anyhow::Result<Self> {
        let engine = Arc::new(RegoRoutingEngine::new(config)?);
        let routing_agent = Arc::new(RegoRoutingAgent::new(engine.clone()));
        Ok(Self {
            engine,
            routing_agent,
        })
    }

    /// Returns the shared live [`RegoRoutingEngine`].
    pub fn engine(&self) -> &Arc<RegoRoutingEngine> {
        &self.engine
    }

    /// Returns the Hardy [`RegoRoutingAgent`] backed by the shared engine.
    pub fn routing_agent(&self) -> &Arc<RegoRoutingAgent> {
        &self.routing_agent
    }

    /// Hydrates live blacklist entries and custom Rego policy overrides from SQLite.
    pub fn load_from_storage(&self, conn: &Connection) -> anyhow::Result<()> {
        let mut stmt = conn.prepare(
            "SELECT id, eid_pattern, reason, enabled, created_at, created_by
             FROM rego_blacklist ORDER BY created_at DESC, eid_pattern ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let enabled_i: i64 = row.get(3)?;
            Ok(BlacklistEntry {
                id: row.get(0)?,
                eid_pattern: row.get(1)?,
                reason: row.get(2)?,
                enabled: enabled_i != 0,
                created_at: row.get(4)?,
                created_by: row.get(5)?,
            })
        })?;

        let mut entries = Vec::new();
        for r in rows {
            entries.push(r?);
        }
        self.engine.replace_blacklist(entries);

        // Ensure legacy databases without custom_routing_rego are upgraded gracefully.
        let _ = conn.execute(
            "ALTER TABLE rego_policy_config ADD COLUMN custom_routing_rego TEXT",
            [],
        );

        type PolicyRow = (
            String,
            i64,
            i64,
            Option<String>,
            Option<String>,
            Option<String>,
        );
        let policy_row: Option<PolicyRow> = rusqlite::OptionalExtension::optional(
            conn.query_row(
                "SELECT active_profile, hop_limit, treb_block_type, custom_ingress_rego, custom_egress_rego, custom_routing_rego
                 FROM rego_policy_config WHERE id = 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            ),
        )?;

        if let Some((profile, hop_limit, treb_block_type, custom_in, custom_eg, custom_rt)) =
            policy_row
        {
            let hl = u8::try_from(hop_limit).unwrap_or(16).max(1);
            let tb = u64::try_from(treb_block_type).unwrap_or(blocks::DEFAULT_BLOCK_TYPE_TREB);
            self.engine
                .update_policy_with_routing(profile, hl, tb, custom_in, custom_eg, custom_rt)?;
        }

        Ok(())
    }
}

#[async_trait]
impl WebModule for RegoRoutingModule {
    fn id(&self) -> &'static str {
        "rego_routing"
    }

    fn name(&self) -> &'static str {
        "Rego Routing & Filtering"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn filter_packs(&self) -> Vec<FilterPack> {
        vec![build_filter_pack(self.engine.clone())]
    }

    fn migrate(&self, conn: &Connection) -> anyhow::Result<()> {
        conn.execute_batch(INITIAL_SCHEMA_SQL)?;
        self.load_from_storage(conn)?;
        Ok(())
    }

    async fn register_bpa(&self, ctx: &ModuleContext) -> anyhow::Result<()> {
        let mut eids = vec![ctx.config.node_id.clone()];
        if let Some(cs) = &ctx.config.callsign
            && !cs.trim().is_empty()
        {
            eids.push(cs.trim().to_string());
        }
        self.engine.set_node_eids(eids);

        let conn_lock = ctx.internal_storage.connection();
        let conn = conn_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("Database lock poisoned during register_bpa"))?;
        self.load_from_storage(&conn)?;
        Ok(())
    }

    fn api_routes(&self, ctx: &ModuleContext) -> Router<()> {
        let state = RegoRouteState {
            ctx: ctx.clone(),
            engine: self.engine.clone(),
        };

        Router::new()
            .route(
                "/blacklist",
                get(routes::list_blacklist).post(routes::create_blacklist),
            )
            .route(
                "/blacklist/{id}",
                patch(routes::toggle_blacklist).delete(routes::delete_blacklist),
            )
            .route(
                "/policy",
                get(routes::get_policy).put(routes::update_policy),
            )
            .route("/decisions", get(routes::list_decisions))
            .route("/decisions/clear", post(routes::clear_decisions))
            .with_state(state)
    }
}
