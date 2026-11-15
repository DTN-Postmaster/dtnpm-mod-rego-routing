//! Hardy BPA [`RoutingAgent`] implementation driven by the Rego routing engine,
//! including dynamic route management helpers prepared for Hardy `feat/spray-n-wait`.

use std::sync::Arc;

use hardy_async::async_trait;
use hardy_bpa::routing::{RouteAction, RoutingAgent, RoutingSink};
use hardy_bpv7::{eid::Eid, eid::NodeId};
use hardy_eid_patterns::EidPattern;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::engine::RegoRoutingEngine;
use crate::error::RegoRoutingError;

/// Default RIB priority used for Rego-managed routes (lower takes precedence if needed,
/// using standard moderate priority `100`).
pub const DEFAULT_REGO_ROUTE_PRIORITY: u32 = 100;

/// Hardy BPA [`RoutingAgent`] that synchronizes node identity and exposes
/// programmatic route helpers for dynamic / Spray-and-Wait / APRS routing rules.
pub struct RegoRoutingAgent {
    engine: Arc<RegoRoutingEngine>,
    sink: RwLock<Option<Box<dyn RoutingSink>>>,
}

impl std::fmt::Debug for RegoRoutingAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegoRoutingAgent").finish()
    }
}

impl RegoRoutingAgent {
    /// Creates a new [`RegoRoutingAgent`] backed by `engine`.
    pub fn new(engine: Arc<RegoRoutingEngine>) -> Self {
        Self {
            engine,
            sink: RwLock::new(None),
        }
    }

    /// Adds or ensures a route in Hardy's RIB via the registered [`RoutingSink`].
    pub async fn upsert_route(
        &self,
        pattern: EidPattern,
        action: RouteAction,
        priority: u32,
    ) -> Result<bool, RegoRoutingError> {
        let guard = self.sink.read().await;
        let Some(sink) = guard.as_ref() else {
            return Err(RegoRoutingError::InvalidConfig(
                "RegoRoutingAgent is not registered with a Hardy BPA instance".to_string(),
            ));
        };
        sink.add_route(pattern, action, priority)
            .await
            .map_err(|e| RegoRoutingError::InvalidConfig(format!("RIB add_route failed: {e}")))
    }

    /// Removes a specific route from Hardy's RIB via the registered [`RoutingSink`].
    pub async fn remove_route(
        &self,
        pattern: &EidPattern,
        action: &RouteAction,
        priority: u32,
    ) -> Result<bool, RegoRoutingError> {
        let guard = self.sink.read().await;
        let Some(sink) = guard.as_ref() else {
            return Err(RegoRoutingError::InvalidConfig(
                "RegoRoutingAgent is not registered with a Hardy BPA instance".to_string(),
            ));
        };
        sink.remove_route(pattern, action, priority)
            .await
            .map_err(|e| RegoRoutingError::InvalidConfig(format!("RIB remove_route failed: {e}")))
    }

    /// Helper registering a peer next-hop route for Spray-and-Wait dissemination
    /// (compatible with `hardy` `feat/spray-n-wait` relay contacts).
    pub async fn add_spray_route(
        &self,
        destination_pattern: EidPattern,
        next_hop: Eid,
        priority: Option<u32>,
    ) -> Result<bool, RegoRoutingError> {
        self.upsert_route(
            destination_pattern,
            RouteAction::Via(next_hop),
            priority.unwrap_or(DEFAULT_REGO_ROUTE_PRIORITY),
        )
        .await
    }

    /// Helper removing a Spray-and-Wait peer route.
    pub async fn remove_spray_route(
        &self,
        destination_pattern: &EidPattern,
        next_hop: Eid,
        priority: Option<u32>,
    ) -> Result<bool, RegoRoutingError> {
        self.remove_route(
            destination_pattern,
            &RouteAction::Via(next_hop),
            priority.unwrap_or(DEFAULT_REGO_ROUTE_PRIORITY),
        )
        .await
    }
}

#[async_trait]
impl RoutingAgent for RegoRoutingAgent {
    async fn on_register(&self, sink: Box<dyn RoutingSink>, node_ids: &[NodeId]) {
        let eid_strings: Vec<String> = node_ids.iter().map(ToString::to_string).collect();
        info!(
            node_ids = ?eid_strings,
            "RegoRoutingAgent registered with Hardy BPA"
        );
        self.engine.set_node_eids(eid_strings);
        let mut guard = self.sink.write().await;
        *guard = Some(sink);
    }

    async fn on_unregister(&self) {
        let mut guard = self.sink.write().await;
        if guard.take().is_some() {
            warn!("RegoRoutingAgent unregistered from Hardy BPA");
        }
    }
}
