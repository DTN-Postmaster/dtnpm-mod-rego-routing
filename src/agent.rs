//! Hardy BPA [`RoutingAgent`] implementation driven by the Rego routing engine,
//! including dynamic `RouteAction::Via` and `RouteAction::ForwardReplicate`
//! route management for APRS and Spray-and-Wait (Hardy `main-dtnpm`).

use std::collections::HashSet;
use std::sync::Arc;

use hardy_async::async_trait;
use hardy_bpa::routing::{RouteAction, RoutingAgent, RoutingSink};
use hardy_bpv7::{bundle::Bundle, eid::Eid, eid::NodeId, status_report::ReasonCode};
use hardy_eid_patterns::EidPattern;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::engine::{DynamicRouteCommand, RegoRoutingEngine, resolve_next_hop_eid};
use crate::error::RegoRoutingError;
use crate::policy::DesiredRoute;

/// Default RIB priority used for Rego-managed routes (lower takes precedence if needed,
/// using standard moderate priority `100`).
pub const DEFAULT_REGO_ROUTE_PRIORITY: u32 = 100;

/// Hardy BPA [`RoutingAgent`] that synchronizes node identity and exposes
/// programmatic route helpers for dynamic / Spray-and-Wait / APRS routing rules.
pub struct RegoRoutingAgent {
    engine: Arc<RegoRoutingEngine>,
    sink: RwLock<Option<Arc<dyn RoutingSink>>>,
    stop_tx: RwLock<Option<tokio::sync::watch::Sender<bool>>>,
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
            stop_tx: RwLock::new(None),
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

    /// Registers an opportunistic `RouteAction::ForwardReplicate` route for
    /// Spray-and-Wait dissemination so Hardy BPA retains the bundle in storage
    /// after forwarding copies to relay contacts.
    pub async fn add_spray_route(
        &self,
        destination_pattern: EidPattern,
        next_hop: Eid,
        priority: Option<u32>,
    ) -> Result<bool, RegoRoutingError> {
        self.upsert_route(
            destination_pattern,
            RouteAction::ForwardReplicate(next_hop),
            priority.unwrap_or(DEFAULT_REGO_ROUTE_PRIORITY),
        )
        .await
    }

    /// Registers an opportunistic `RouteAction::ForwardReplicate` route for
    /// `bundle` only if its tracked Spray-and-Wait permit quota is still in the
    /// Spray phase (`L > 1`). Returns `Ok(false)` when in the Wait phase (`L <= 1`).
    pub async fn add_spray_route_for_bundle(
        &self,
        destination_pattern: EidPattern,
        next_hop: Eid,
        bundle: &Bundle,
        priority: Option<u32>,
    ) -> Result<bool, RegoRoutingError> {
        if let Some(quota) = self.engine.tracked_spray_quota(bundle)
            && quota <= 1
        {
            return Ok(false);
        }
        self.add_spray_route(destination_pattern, next_hop, priority)
            .await
    }

    /// Removes a Spray-and-Wait `RouteAction::ForwardReplicate` peer route.
    pub async fn remove_spray_route(
        &self,
        destination_pattern: &EidPattern,
        next_hop: Eid,
        priority: Option<u32>,
    ) -> Result<bool, RegoRoutingError> {
        self.remove_route(
            destination_pattern,
            &RouteAction::ForwardReplicate(next_hop),
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
        let sink_arc: Arc<dyn RoutingSink> = Arc::from(sink);
        {
            let mut guard = self.sink.write().await;
            *guard = Some(sink_arc.clone());
        }

        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        {
            let mut guard = self.stop_tx.write().await;
            *guard = Some(stop_tx);
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<DynamicRouteCommand>(256);
        self.engine.set_route_sender(tx);
        let cmd_sink = sink_arc.clone();
        tokio::spawn(async move {
            const MAX_INSTALLED_ROUTES: usize = 4096;
            let mut installed: HashSet<(Eid, RouteAction)> = HashSet::new();
            let mut order: std::collections::VecDeque<(Eid, RouteAction)> =
                std::collections::VecDeque::new();
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    DynamicRouteCommand::Add {
                        pattern: pattern_eid,
                        action,
                    } => {
                        let key = (pattern_eid.clone(), action.clone());
                        if !installed.insert(key.clone()) {
                            continue;
                        }
                        order.push_back(key);
                        if order.len() > MAX_INSTALLED_ROUTES
                            && let Some(oldest) = order.pop_front()
                        {
                            installed.remove(&oldest);
                        }
                        let pattern: EidPattern = pattern_eid.into();
                        match cmd_sink
                            .add_route(pattern.clone(), action.clone(), DEFAULT_REGO_ROUTE_PRIORITY)
                            .await
                        {
                            Ok(added) => {
                                info!(
                                    pattern = %pattern,
                                    action = %action,
                                    added,
                                    "RegoRoutingAgent installed dynamic route from Rego decision"
                                );
                            }
                            Err(err) => {
                                warn!(
                                    pattern = %pattern,
                                    action = %action,
                                    "RegoRoutingAgent failed to add dynamic route: {err}"
                                );
                            }
                        }
                    }
                    DynamicRouteCommand::Remove {
                        pattern: pattern_eid,
                        action,
                    } => {
                        let key = (pattern_eid.clone(), action.clone());
                        installed.remove(&key);
                        let pattern: EidPattern = pattern_eid.into();
                        match cmd_sink
                            .remove_route(&pattern, &action, DEFAULT_REGO_ROUTE_PRIORITY)
                            .await
                        {
                            Ok(removed) => {
                                info!(
                                    pattern = %pattern,
                                    action = %action,
                                    removed,
                                    "RegoRoutingAgent removed dynamic route"
                                );
                            }
                            Err(err) => {
                                warn!(
                                    pattern = %pattern,
                                    action = %action,
                                    "RegoRoutingAgent failed to remove dynamic route: {err}"
                                );
                            }
                        }
                    }
                }
            }
        });

        let engine = self.engine.clone();
        let notify = engine.reconcile_notifier();
        tokio::spawn(async move {
            let mut active_routes: HashSet<(EidPattern, RouteAction, u32)> = HashSet::new();
            reconcile_routing_table(&engine, &sink_arc, &mut active_routes).await;

            loop {
                tokio::select! {
                    _ = notify.notified() => {
                        reconcile_routing_table(&engine, &sink_arc, &mut active_routes).await;
                    }
                    res = stop_rx.changed() => {
                        if res.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
    }

    async fn on_unregister(&self) {
        self.engine.clear_route_sender();
        if let Some(tx) = self.stop_tx.write().await.take() {
            let _ = tx.send(true);
        }
        let mut guard = self.sink.write().await;
        if guard.take().is_some() {
            warn!("RegoRoutingAgent unregistered from Hardy BPA");
        }
    }
}

fn parse_desired_route(desired: &DesiredRoute) -> Option<(EidPattern, RouteAction, u32)> {
    let pattern: EidPattern = match desired.pattern.parse() {
        Ok(p) => p,
        Err(err) => {
            warn!(
                pattern = %desired.pattern,
                "Ignoring invalid Rego routing pattern: {err}"
            );
            return None;
        }
    };

    let action = match desired.action.to_ascii_uppercase().as_str() {
        "FORWARD_REPLICATE" => {
            let hop_str = desired.next_hop.as_deref()?;
            let hop = resolve_next_hop_eid(hop_str)?;
            RouteAction::ForwardReplicate(hop)
        }
        "VIA" => {
            let hop_str = desired.next_hop.as_deref()?;
            let hop = resolve_next_hop_eid(hop_str)?;
            RouteAction::Via(hop)
        }
        "REFLECT" => RouteAction::Reflect,
        "DROP" => {
            let reason = desired
                .reason_code
                .and_then(|c| ReasonCode::try_from(c).ok());
            RouteAction::Drop(reason)
        }
        other => {
            warn!("Ignoring unknown Rego routing action '{other}'");
            return None;
        }
    };

    Some((pattern, action, desired.priority))
}

async fn reconcile_routing_table(
    engine: &RegoRoutingEngine,
    sink: &Arc<dyn RoutingSink>,
    active: &mut HashSet<(EidPattern, RouteAction, u32)>,
) {
    let desired_list = match engine.evaluate_routing_table() {
        Ok(list) => list,
        Err(err) => {
            warn!("Rego routing.rego evaluation failed: {err}");
            return;
        }
    };

    let mut desired_set: HashSet<(EidPattern, RouteAction, u32)> = HashSet::new();
    for item in &desired_list {
        if let Some(parsed) = parse_desired_route(item) {
            desired_set.insert(parsed);
        }
    }

    let to_remove: Vec<(EidPattern, RouteAction, u32)> =
        active.difference(&desired_set).cloned().collect();
    for (pattern, action, priority) in &to_remove {
        match sink.remove_route(pattern, action, *priority).await {
            Ok(removed) => {
                info!(
                    pattern = %pattern,
                    action = %action,
                    priority,
                    removed,
                    "RegoRoutingAgent removed declarative routing.rego route"
                );
            }
            Err(err) => {
                warn!(
                    pattern = %pattern,
                    action = %action,
                    priority,
                    "RegoRoutingAgent failed to remove declarative route: {err}"
                );
            }
        }
    }

    let to_add: Vec<(EidPattern, RouteAction, u32)> =
        desired_set.difference(active).cloned().collect();
    for (pattern, action, priority) in &to_add {
        match sink
            .add_route(pattern.clone(), action.clone(), *priority)
            .await
        {
            Ok(added) => {
                info!(
                    pattern = %pattern,
                    action = %action,
                    priority,
                    added,
                    "RegoRoutingAgent installed declarative routing.rego route"
                );
            }
            Err(err) => {
                warn!(
                    pattern = %pattern,
                    action = %action,
                    priority,
                    "RegoRoutingAgent failed to add declarative route: {err}"
                );
            }
        }
    }

    *active = desired_set;
}
