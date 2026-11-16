//! Custom Hardy [`Rib`] decorator evaluating per-bundle `data.dtn.routing.decide`
//! rules via [`RegoRoutingEngine`] while delegating local services, admin endpoints,
//! and fallback routes to Hardy's [`DefaultRib`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use hardy_async::{CancellationToken, async_trait};
use hardy_bpa::bundle::Bundle;
use hardy_bpa::cla::ClaAddressType;
use hardy_bpa::routing::{
    Decision, DefaultRib, DispatchAction, RegisteredCla, RegisteredService, Result as RibResult,
    Rib, RibSnapshot, RoutingAgent, WaitingPoller,
};
use hardy_bpv7::eid::{Eid, NodeId};
use hardy_bpv7::status_report::ReasonCode;
use tracing::{debug, warn};

use crate::engine::RegoRoutingEngine;

/// Decorator around Hardy's [`DefaultRib`] that evaluates per-bundle Rego routing
/// decisions (`data.dtn.routing.decide`) before falling back to [`DefaultRib`].
pub struct RegoRib {
    inner: Arc<DefaultRib>,
    engine: Arc<RegoRoutingEngine>,
    peers: RwLock<HashMap<NodeId, Vec<u32>>>,
    peer_version: AtomicU64,
    cancel_token: CancellationToken,
    poll_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for RegoRib {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegoRib").finish()
    }
}

impl RegoRib {
    /// Wraps `inner` [`DefaultRib`] with per-bundle Rego routing powered by `engine`.
    pub fn new(inner: Arc<DefaultRib>, engine: Arc<RegoRoutingEngine>) -> Self {
        Self {
            inner,
            engine,
            peers: RwLock::new(HashMap::new()),
            peer_version: AtomicU64::new(0),
            cancel_token: CancellationToken::new(),
            poll_task: Mutex::new(None),
        }
    }

    fn combine_snapshot(&self, inner: RibSnapshot) -> RibSnapshot {
        RibSnapshot(
            inner
                .0
                .wrapping_add(self.peer_version.load(Ordering::Acquire))
                .wrapping_add(self.engine.policy_version()),
        )
    }

    fn connected_peers_snapshot(&self) -> Vec<(NodeId, u32)> {
        let guard = self.peers.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::with_capacity(guard.len());
        for (node_id, peer_ids) in guard.iter() {
            for &peer_id in peer_ids {
                out.push((node_id.clone(), peer_id));
            }
        }
        out
    }
}

#[async_trait]
impl Rib for RegoRib {
    fn decide(&self, bundle: &Bundle) -> Decision {
        let peer_ver = self.peer_version.load(Ordering::Acquire);
        let policy_ver = self.engine.policy_version();
        let default_decision = self.inner.decide(bundle);
        let seen = RibSnapshot(
            default_decision
                .seen
                .0
                .wrapping_add(peer_ver)
                .wrapping_add(policy_ver),
        );

        // Never override local administrative endpoints or local service deliveries.
        if matches!(
            default_decision.action,
            Some(DispatchAction::AdminEndpoint | DispatchAction::Deliver(_))
        ) {
            return Decision {
                action: default_decision.action,
                seen,
            };
        }

        let connected_peers = self.connected_peers_snapshot();
        let rego_decision = match self.engine.evaluate_rib_decide(bundle, &connected_peers) {
            Ok(Some(dec)) => dec,
            Ok(None) => {
                return Decision {
                    action: default_decision.action,
                    seen,
                };
            }
            Err(err) => {
                warn!("RegoRib::decide evaluation failed (falling back to DefaultRib): {err}");
                return Decision {
                    action: default_decision.action,
                    seen,
                };
            }
        };

        match rego_decision.action.as_str() {
            "FALLBACK" => Decision {
                action: default_decision.action,
                seen,
            },
            "WAIT" => Decision { action: None, seen },
            "DROP" => {
                let reason = rego_decision
                    .reason_code
                    .and_then(|c| ReasonCode::try_from(c).ok());
                Decision {
                    action: Some(DispatchAction::Drop(reason)),
                    seen,
                }
            }
            "FORWARD" | "FORWARD_REPLICATE" => {
                let retain = rego_decision
                    .retain
                    .unwrap_or(rego_decision.action == "FORWARD_REPLICATE");
                let Some(next_hop_str) = rego_decision.next_hop.as_deref() else {
                    warn!("RegoRib::decide FORWARD missing next_hop; falling back to Wait");
                    return Decision { action: None, seen };
                };
                let Ok(next_hop_eid) = next_hop_str.parse::<Eid>() else {
                    warn!("RegoRib::decide invalid next_hop EID '{next_hop_str}'; waiting");
                    return Decision { action: None, seen };
                };
                let Ok(node_id) = NodeId::try_from(next_hop_eid.clone()) else {
                    warn!("RegoRib::decide next_hop '{next_hop_str}' is not a NodeId; waiting");
                    return Decision { action: None, seen };
                };

                let matched = match rego_decision.peer_id {
                    Some(wanted_peer) => connected_peers
                        .iter()
                        .find(|(n, p)| *n == node_id && *p == wanted_peer),
                    None => connected_peers.iter().find(|(n, _)| *n == node_id),
                };

                if let Some((_, peer)) = matched {
                    Decision {
                        action: Some(DispatchAction::Forward {
                            peer: *peer,
                            next_hop: Eid::from(node_id),
                            retain,
                        }),
                        seen,
                    }
                } else {
                    debug!(
                        next_hop = %next_hop_str,
                        "RegoRib::decide target peer not connected; parking bundle in Waiting"
                    );
                    Decision { action: None, seen }
                }
            }
            other => {
                warn!("RegoRib::decide unknown action '{other}'; falling back to DefaultRib");
                Decision {
                    action: default_decision.action,
                    seen,
                }
            }
        }
    }

    fn table_snapshot(&self) -> RibSnapshot {
        self.combine_snapshot(self.inner.table_snapshot())
    }

    fn table_changed_since(&self, seen: &RibSnapshot) -> bool {
        self.table_snapshot() != *seen
    }

    fn find_service(&self, to: &Eid) -> Option<Arc<RegisteredService>> {
        self.inner.find_service(to)
    }

    fn start(&self, poller: Arc<dyn WaitingPoller>) {
        let cancel_token = self.cancel_token.clone();
        let notify = self.engine.rib_policy_notifier();
        let poller_clone = poller.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        break;
                    }
                    _ = notify.notified() => {
                        poller_clone.clone().poll_waiting(cancel_token.clone()).await;
                    }
                }
            }
        });

        if let Some(prev) = self
            .poll_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(handle)
        {
            prev.abort();
        }

        self.inner.start(poller);
    }

    async fn shutdown(&self) {
        self.cancel_token.cancel();
        let handle = self
            .poll_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(h) = handle {
            let _ = h.await;
        }
        self.inner.shutdown().await;
    }

    async fn shutdown_agents(&self) {
        self.inner.shutdown_agents().await;
    }

    async fn register_agent(
        &self,
        name: String,
        agent: Arc<dyn RoutingAgent>,
    ) -> RibResult<Vec<NodeId>> {
        self.inner.register_agent(name, agent).await
    }

    async fn add_forward(&self, node_id: NodeId, peer: u32) -> RibResult<bool> {
        {
            let mut guard = self.peers.write().unwrap_or_else(|e| e.into_inner());
            let entry = guard.entry(node_id.clone()).or_default();
            if !entry.contains(&peer) {
                entry.push(peer);
            }
        }
        self.peer_version.fetch_add(1, Ordering::Release);
        self.inner.add_forward(node_id, peer).await
    }

    async fn remove_forward(&self, node_id: NodeId, peer: u32) -> bool {
        {
            let mut guard = self.peers.write().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = guard.get_mut(&node_id) {
                entry.retain(|&p| p != peer);
                if entry.is_empty() {
                    guard.remove(&node_id);
                }
            }
        }
        self.peer_version.fetch_add(1, Ordering::Release);
        self.inner.remove_forward(node_id, peer).await
    }

    async fn add_service(&self, eid: Eid, service: Arc<RegisteredService>) -> RibResult<bool> {
        self.inner.add_service(eid, service).await
    }

    async fn remove_service(&self, eid: &Eid, service: Arc<RegisteredService>) -> bool {
        self.inner.remove_service(eid, service).await
    }

    fn add_address_type(&self, address_type: ClaAddressType, cla: Arc<RegisteredCla>) {
        self.inner.add_address_type(address_type, cla);
    }

    fn remove_address_type(&self, address_type: &ClaAddressType) {
        self.inner.remove_address_type(address_type);
    }
}
