//! Core stateful Rego routing evaluation engine shared between Hardy BPA filters
//! and the DTN Postmaster REST/SQLite administration plane.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use hardy_bpa::bundle::BundleMetadata;
use hardy_bpa::cla::ClaAddress;
use hardy_bpa::routing::RouteAction;
use hardy_bpv7::{
    block, bundle::Bundle, bundle_age::BundleAge, dtn_time::DtnTime, eid::Eid, eid::NodeId,
    hop_info::HopInfo, reader::Reader, reader::ReaderExt,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::warn;

use crate::blocks::{
    BLOCK_TYPE_BUNDLE_AGE, BLOCK_TYPE_HOP_COUNT, BLOCK_TYPE_MESH_ROUTING, BLOCK_TYPE_PREVIOUS_NODE,
    BLOCK_TYPE_SPRAY_PERMIT, DEFAULT_BLOCK_TYPE_TREB, MeshRoutingData, TrebData,
    decode_cbor_to_json, decode_spray_permit,
};
use crate::error::RegoRoutingError;
use crate::policy::{DesiredRoute, PolicySources, PolicySuite, RegoDecision, RibDecision};

/// Maximum accepted EID pattern length (anti-DoS / SQLite hygiene).
pub const MAX_EID_PATTERN_LEN: usize = 256;

/// Persistent source blacklist entry editable from WebUI / REST API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlacklistEntry {
    pub id: String,
    pub eid_pattern: String,
    pub reason: String,
    pub enabled: bool,
    pub created_at: i64,
    pub created_by: String,
}

/// Recent Rego evaluation audit entry exposed to the WebUI audit table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionAuditEntry {
    pub id: u64,
    pub timestamp: i64,
    pub phase: String,
    pub bundle_id: String,
    pub source: String,
    pub destination: String,
    pub peer_eid: Option<String>,
    pub action: String,
    pub reason: String,
    pub route_key: Option<String>,
}

/// Runtime configuration for the Rego routing engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegoRoutingConfig {
    pub local_eid: String,
    pub node_eids: Vec<String>,
    pub callsign: Option<String>,
    pub is_digipeater: bool,
    pub supported_aliases: Vec<String>,
    pub trapped_aliases: Vec<String>,
    pub hop_limit: u8,
    pub treb_block_type: u64,
    pub record_treb: bool,
    pub active_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_ingress_rego: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_egress_rego: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_routing_rego: Option<String>,
    pub max_seen_cache: usize,
    pub max_spray_tracker: usize,
    pub max_audit_entries: usize,
}

impl Default for RegoRoutingConfig {
    fn default() -> Self {
        Self {
            local_eid: "ipn:1.0".to_string(),
            node_eids: vec!["ipn:1.0".to_string()],
            callsign: None,
            is_digipeater: false,
            supported_aliases: vec!["WIDE1".to_string(), "WIDE2".to_string()],
            trapped_aliases: vec![
                "WIDE3".to_string(),
                "WIDE4".to_string(),
                "WIDE5".to_string(),
                "WIDE6".to_string(),
                "WIDE7".to_string(),
            ],
            hop_limit: 16,
            treb_block_type: DEFAULT_BLOCK_TYPE_TREB,
            record_treb: false,
            active_profile: "default".to_string(),
            policy_dir: None,
            custom_ingress_rego: None,
            custom_egress_rego: None,
            custom_routing_rego: None,
            max_seen_cache: 4096,
            max_spray_tracker: 4096,
            max_audit_entries: 500,
        }
    }
}

/// Resolves a Rego `route_key` (either a full EID like `"dtn://statc/files"` or a
/// callsign like `"STATB"`) into the administrative node EID (`"dtn://statc/"` / `"dtn://statb/"`).
#[must_use]
pub fn resolve_next_hop_eid(route_key: &str) -> Option<Eid> {
    let trimmed = route_key.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(eid) = trimmed.parse::<Eid>() {
        return Some(match eid {
            Eid::Dtn { node_name, .. } => Eid::Dtn {
                node_name,
                service_name: "".into(),
            },
            Eid::Ipn { fqnn, .. } => Eid::Ipn {
                fqnn,
                service_number: 0,
            },
            other => other,
        });
    }
    format!("dtn://{}/", trimmed.to_ascii_lowercase())
        .parse::<Eid>()
        .ok()
}

/// Validates and normalizes an EID or wildcard pattern before storage or Rego injection.
pub fn validate_eid_pattern(pattern: &str) -> Result<String, RegoRoutingError> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return Err(RegoRoutingError::InvalidEidPattern(
            "EID pattern must not be empty".to_string(),
        ));
    }
    if trimmed.len() > MAX_EID_PATTERN_LEN {
        return Err(RegoRoutingError::InvalidEidPattern(format!(
            "EID pattern exceeds {MAX_EID_PATTERN_LEN} characters"
        )));
    }
    if !trimmed.is_ascii()
        || trimmed
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(RegoRoutingError::InvalidEidPattern(
            "EID pattern must contain printable non-whitespace ASCII characters".to_string(),
        ));
    }
    if !trimmed.contains(':') {
        return Err(RegoRoutingError::InvalidEidPattern(
            "EID pattern must include a BPv7 URI scheme (e.g., dtn://... or ipn:...)".to_string(),
        ));
    }
    if trimmed == "*:*" {
        return Err(RegoRoutingError::InvalidEidPattern(
            "Wildcard-all scheme patterns are rejected for operational safety".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

struct BoundedSeenCache {
    order: VecDeque<String>,
    set: HashSet<String>,
    cap: usize,
}

impl BoundedSeenCache {
    fn new(cap: usize) -> Self {
        Self {
            order: VecDeque::new(),
            set: HashSet::new(),
            cap: cap.max(16),
        }
    }

    fn insert(&mut self, key: String) {
        if self.set.contains(&key) {
            return;
        }
        if self.order.len() >= self.cap
            && let Some(oldest) = self.order.pop_front()
        {
            self.set.remove(&oldest);
        }
        self.set.insert(key.clone());
        self.order.push_back(key);
    }

    fn snapshot(&self) -> Vec<String> {
        self.order.iter().cloned().collect()
    }
}

struct BoundedSprayTracker {
    order: VecDeque<String>,
    quotas: HashMap<String, u32>,
    cap: usize,
}

impl BoundedSprayTracker {
    fn new(cap: usize) -> Self {
        Self {
            order: VecDeque::new(),
            quotas: HashMap::new(),
            cap: cap.max(16),
        }
    }

    fn get(&self, key: &str) -> Option<u32> {
        self.quotas.get(key).copied()
    }

    fn set(&mut self, key: String, quota: u32) {
        if !self.quotas.contains_key(&key) {
            if self.order.len() >= self.cap
                && let Some(oldest) = self.order.pop_front()
            {
                self.quotas.remove(&oldest);
            }
            self.order.push_back(key.clone());
        }
        self.quotas.insert(key, quota);
    }
}

/// Dynamic RIB update command dispatched from Rego policy evaluation to [`crate::agent::RegoRoutingAgent`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DynamicRouteCommand {
    Add { pattern: Eid, action: RouteAction },
    Remove { pattern: Eid, action: RouteAction },
}

/// Connected neighbor peer discovered via a CLA wrapper or registered manually.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NeighborPeer {
    pub peer_eid: String,
    pub cla_name: String,
    pub cla_type: String,
    pub cla_addr: String,
}

struct RegoRoutingState {
    config: RegoRoutingConfig,
    suite: PolicySuite,
    blacklist: Vec<BlacklistEntry>,
    seen_cache: BoundedSeenCache,
    spray_tracker: BoundedSprayTracker,
    decision_log: VecDeque<DecisionAuditEntry>,
    next_audit_id: u64,
    route_tx: Option<tokio::sync::mpsc::Sender<DynamicRouteCommand>>,
    peers: HashMap<(String, String), Vec<NeighborPeer>>,
    reconcile_notify: Arc<tokio::sync::Notify>,
    rib_policy_notify: Arc<tokio::sync::Notify>,
    policy_version: Arc<AtomicU64>,
}

impl RegoRoutingState {
    fn enabled_blacklist_sources(&self) -> Vec<String> {
        self.blacklist
            .iter()
            .filter(|b| b.enabled)
            .map(|b| b.eid_pattern.clone())
            .collect()
    }

    fn bump_policy_version(&self) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        self.policy_version.fetch_add(1, Ordering::Release);
        (
            self.reconcile_notify.clone(),
            self.rib_policy_notify.clone(),
        )
    }
}

/// Thread-safe facade used concurrently by Hardy BPA pipeline filters and the REST API.
#[derive(Clone)]
pub struct RegoRoutingEngine {
    state: Arc<RwLock<RegoRoutingState>>,
}

impl std::fmt::Debug for RegoRoutingEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegoRoutingEngine").finish()
    }
}

impl RegoRoutingEngine {
    /// Initializes a new [`RegoRoutingEngine`] and compiles initial Rego policies.
    pub fn new(config: RegoRoutingConfig) -> Result<Self, RegoRoutingError> {
        let base = PolicySources::from_dir_or_default(config.policy_dir.as_deref())?;
        let sources = base.with_all_overrides(
            config.custom_ingress_rego.as_deref(),
            config.custom_egress_rego.as_deref(),
            config.custom_routing_rego.as_deref(),
        )?;
        let suite = PolicySuite::compile(sources)?;
        let seen_cap = config.max_seen_cache;
        let spray_cap = config.max_spray_tracker;

        Ok(Self {
            state: Arc::new(RwLock::new(RegoRoutingState {
                config,
                suite,
                blacklist: Vec::new(),
                seen_cache: BoundedSeenCache::new(seen_cap),
                spray_tracker: BoundedSprayTracker::new(spray_cap),
                decision_log: VecDeque::new(),
                next_audit_id: 1,
                route_tx: None,
                peers: HashMap::new(),
                reconcile_notify: Arc::new(tokio::sync::Notify::new()),
                rib_policy_notify: Arc::new(tokio::sync::Notify::new()),
                policy_version: Arc::new(AtomicU64::new(0)),
            })),
        })
    }

    /// Returns the [`tokio::sync::Notify`] handle signaled whenever neighbor peers,
    /// blacklist rules, or `routing.rego` policies change.
    pub fn reconcile_notifier(&self) -> Arc<tokio::sync::Notify> {
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        guard.reconcile_notify.clone()
    }

    /// Returns the [`tokio::sync::Notify`] handle signaled whenever blacklist rules
    /// or Rego policies change (dedicated to `RegoRib::start`).
    pub fn rib_policy_notifier(&self) -> Arc<tokio::sync::Notify> {
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        guard.rib_policy_notify.clone()
    }

    /// Returns the monotonic policy/blacklist version counter for `RegoRib` snapshots.
    pub fn policy_version(&self) -> u64 {
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        guard.policy_version.load(Ordering::Acquire)
    }

    /// Records or updates connected neighbor peers for `(cla_name, cla_addr)` and
    /// triggers declarative RIB reconciliation.
    pub fn upsert_peers(
        &self,
        cla_name: &str,
        cla_type: &str,
        cla_addr: &str,
        peer_eids: Vec<String>,
    ) {
        let notify = {
            let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
            let key = (cla_name.to_string(), cla_addr.to_string());
            if peer_eids.is_empty() {
                guard.peers.remove(&key);
            } else {
                let entries = peer_eids
                    .into_iter()
                    .map(|peer_eid| NeighborPeer {
                        peer_eid,
                        cla_name: cla_name.to_string(),
                        cla_type: cla_type.to_string(),
                        cla_addr: cla_addr.to_string(),
                    })
                    .collect();
                guard.peers.insert(key, entries);
            }
            guard.reconcile_notify.clone()
        };
        notify.notify_one();
    }

    /// Removes neighbor peers associated with `(cla_name, cla_addr)` and
    /// triggers declarative RIB reconciliation.
    pub fn remove_peers(&self, cla_name: &str, cla_addr: &str) {
        let notify = {
            let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
            guard
                .peers
                .remove(&(cla_name.to_string(), cla_addr.to_string()));
            guard.reconcile_notify.clone()
        };
        notify.notify_one();
    }

    /// Returns a deterministic snapshot of all currently connected neighbor peers.
    pub fn peers_snapshot(&self) -> Vec<NeighborPeer> {
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<NeighborPeer> = guard.peers.values().flatten().cloned().collect();
        out.sort_by(|a, b| {
            a.peer_eid
                .cmp(&b.peer_eid)
                .then_with(|| a.cla_name.cmp(&b.cla_name))
                .then_with(|| a.cla_addr.cmp(&b.cla_addr))
        });
        out
    }

    /// Evaluates `data.dtn.routing.routes` against the current node state and connected neighbor peers.
    pub fn evaluate_routing_table(&self) -> Result<Vec<DesiredRoute>, RegoRoutingError> {
        let (suite, config, blacklist_sources, peers) = {
            let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
            let blacklist_sources = guard.enabled_blacklist_sources();
            let mut peers: Vec<NeighborPeer> = guard.peers.values().flatten().cloned().collect();
            peers.sort_by(|a, b| a.peer_eid.cmp(&b.peer_eid));
            (
                guard.suite.clone(),
                guard.config.clone(),
                blacklist_sources,
                peers,
            )
        };

        let input = serde_json::json!({
            "node": build_routing_node_json(&config, &blacklist_sources),
            "peers": peers,
            "current_dtn_time_ms": DtnTime::now().millisecs(),
        });

        suite.evaluate_routing(&input)
    }

    /// Evaluates per-bundle `data.dtn.routing.decide` for `RegoRib::decide`.
    pub fn evaluate_rib_decide(
        &self,
        bundle: &hardy_bpa::bundle::Bundle,
        connected_peers: &[(NodeId, u32)],
    ) -> Result<Option<RibDecision>, RegoRoutingError> {
        let bundle_id_str = bundle.bpv7.primary.id.to_string();
        let (suite, config, blacklist_sources, neighbor_peers, spray_quota) = {
            let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
            if !guard.suite.has_custom_decide() {
                return Ok(None);
            }
            let blacklist_sources = guard.enabled_blacklist_sources();
            let neighbor_peers: Vec<NeighborPeer> =
                guard.peers.values().flatten().cloned().collect();
            let spray_quota = guard.spray_tracker.get(&bundle_id_str);
            (
                guard.suite.clone(),
                guard.config.clone(),
                blacklist_sources,
                neighbor_peers,
                spray_quota,
            )
        };

        let mut peers_json: Vec<serde_json::Value> = connected_peers
            .iter()
            .map(|(node_id, peer_id)| {
                let peer_eid = Eid::from(node_id.clone()).to_string();
                let meta = neighbor_peers.iter().find(|p| p.peer_eid == peer_eid);
                serde_json::json!({
                    "peer_eid": peer_eid,
                    "node_id": node_id.to_string(),
                    "peer_id": peer_id,
                    "cla_name": meta.map(|m| m.cla_name.as_str()).unwrap_or(""),
                    "cla_addr": meta.map(|m| m.cla_addr.as_str()).unwrap_or(""),
                })
            })
            .collect();
        peers_json.sort_by(|a, b| {
            let ea = a.get("peer_eid").and_then(|v| v.as_str()).unwrap_or("");
            let eb = b.get("peer_eid").and_then(|v| v.as_str()).unwrap_or("");
            ea.cmp(eb)
        });

        let payload_len = bundle
            .bpv7
            .blocks
            .get(&1)
            .map(|b| b.data.end.saturating_sub(b.data.start))
            .unwrap_or(0);
        let block_types: Vec<u64> = bundle
            .bpv7
            .blocks
            .values()
            .map(|b| u64::from(b.block_type))
            .collect();
        let staged_decision = bundle.metadata.slot(&crate::filter::REGO_BUNDLE_DECISION);
        let route_key = staged_decision
            .as_ref()
            .and_then(|s| s.selected_route_key.clone());
        let previous_node = bundle
            .metadata
            .extensions
            .previous_node
            .as_ref()
            .map(ToString::to_string);

        let input = serde_json::json!({
            "bundle": {
                "id": bundle_id_str,
                "source": bundle.bpv7.primary.id.source.to_string(),
                "destination": bundle.bpv7.primary.destination.to_string(),
                "report_to": bundle.bpv7.primary.report_to.to_string(),
                "route_key": route_key,
                "payload_len": payload_len,
                "block_types": block_types,
                "previous_node": previous_node,
                "staged_decision": staged_decision,
                "spray_quota": spray_quota,
            },
            "peers": peers_json,
            "node": build_routing_node_json(&config, &blacklist_sources),
            "current_dtn_time_ms": DtnTime::now().millisecs(),
        });

        suite.evaluate_rib_decide(&input)
    }

    /// Registers the channel used by [`crate::filter::RegoIngressClassifier`] to ask [`crate::agent::RegoRoutingAgent`]
    /// to install or remove dynamic RIB entries (`RouteAction::Via` / `RouteAction::ForwardReplicate`).
    pub fn set_route_sender(&self, tx: tokio::sync::mpsc::Sender<DynamicRouteCommand>) {
        let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
        guard.route_tx = Some(tx);
    }

    /// Clears the dynamic route channel when [`crate::agent::RegoRoutingAgent`] unregisters,
    /// stopping its background RIB installer task.
    pub fn clear_route_sender(&self) {
        let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
        guard.route_tx = None;
    }

    /// Enqueues a non-blocking dynamic `RouteAction::Via(next_hop_eid)` request for `pattern_eid`.
    pub fn request_dynamic_route(&self, pattern_eid: Eid, next_hop_eid: Eid) {
        self.request_dynamic_action(pattern_eid, RouteAction::Via(next_hop_eid));
    }

    /// Enqueues a non-blocking dynamic RIB route installation (`Via` or `ForwardReplicate`) for `pattern_eid`.
    pub fn request_dynamic_action(&self, pattern_eid: Eid, action: RouteAction) {
        self.send_route_command(DynamicRouteCommand::Add {
            pattern: pattern_eid,
            action,
        });
    }

    /// Enqueues a non-blocking dynamic RIB route removal for `pattern_eid`.
    pub fn request_remove_dynamic_action(&self, pattern_eid: Eid, action: RouteAction) {
        self.send_route_command(DynamicRouteCommand::Remove {
            pattern: pattern_eid,
            action,
        });
    }

    fn send_route_command(&self, cmd: DynamicRouteCommand) {
        let tx_opt = {
            let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
            guard.route_tx.clone()
        };
        if let Some(tx) = tx_opt
            && let Err(err) = tx.try_send(cmd)
        {
            warn!("Failed to enqueue dynamic Rego route request: {err}");
        }
    }

    /// Returns a snapshot of configured blacklist entries.
    pub fn blacklist(&self) -> Vec<BlacklistEntry> {
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        guard.blacklist.clone()
    }

    /// Replaces the entire in-memory blacklist (typically after SQLite load).
    pub fn replace_blacklist(&self, entries: Vec<BlacklistEntry>) {
        let (reconcile_notify, rib_notify) = {
            let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
            guard.blacklist = entries;
            guard.bump_policy_version()
        };
        reconcile_notify.notify_one();
        rib_notify.notify_one();
    }

    /// Inserts or replaces an entry in the live blacklist.
    pub fn upsert_blacklist_entry(&self, entry: BlacklistEntry) {
        let (reconcile_notify, rib_notify) = {
            let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = guard
                .blacklist
                .iter_mut()
                .find(|e| e.id == entry.id || e.eid_pattern == entry.eid_pattern)
            {
                *existing = entry;
            } else {
                guard.blacklist.insert(0, entry);
            }
            guard.bump_policy_version()
        };
        reconcile_notify.notify_one();
        rib_notify.notify_one();
    }

    /// Removes a blacklist entry by `id`, returning `true` if found.
    pub fn remove_blacklist_entry(&self, id: &str) -> bool {
        let (removed, reconcile_notify, rib_notify) = {
            let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
            let before = guard.blacklist.len();
            guard.blacklist.retain(|e| e.id != id);
            let (rn, rbn) = guard.bump_policy_version();
            (guard.blacklist.len() != before, rn, rbn)
        };
        if removed {
            reconcile_notify.notify_one();
            rib_notify.notify_one();
        }
        removed
    }

    /// Updates `enabled` on an existing blacklist entry, returning `true` if found.
    pub fn set_blacklist_enabled(&self, id: &str, enabled: bool) -> bool {
        let (updated, reconcile_notify, rib_notify) = {
            let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
            let updated = if let Some(entry) = guard.blacklist.iter_mut().find(|e| e.id == id) {
                entry.enabled = enabled;
                true
            } else {
                false
            };
            let (rn, rbn) = guard.bump_policy_version();
            (updated, rn, rbn)
        };
        if updated {
            reconcile_notify.notify_one();
            rib_notify.notify_one();
        }
        updated
    }

    /// Returns a clone of the current configuration.
    pub fn config(&self) -> RegoRoutingConfig {
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        guard.config.clone()
    }

    /// Updates node local EIDs discovered when Hardy BPA registers the module.
    pub fn set_node_eids(&self, node_eids: Vec<String>) {
        if node_eids.is_empty() {
            return;
        }
        let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
        guard.config.local_eid = node_eids[0].clone();
        guard.config.node_eids = node_eids;
    }

    /// Returns active Rego policy source texts.
    pub fn policy_sources(&self) -> PolicySources {
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        guard.suite.sources().clone()
    }

    /// Validates, compiles, and atomically swaps active Rego policies and tuning parameters.
    pub fn update_policy(
        &self,
        active_profile: String,
        hop_limit: u8,
        treb_block_type: u64,
        custom_ingress_rego: Option<String>,
        custom_egress_rego: Option<String>,
    ) -> Result<(), RegoRoutingError> {
        let current_routing = {
            let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
            guard.config.custom_routing_rego.clone()
        };
        self.update_policy_with_routing(
            active_profile,
            hop_limit,
            treb_block_type,
            custom_ingress_rego,
            custom_egress_rego,
            current_routing,
        )
    }

    /// Validates, compiles, and atomically swaps active Rego policies (including `routing.rego`)
    /// and triggers declarative RIB reconciliation.
    pub fn update_policy_with_routing(
        &self,
        active_profile: String,
        hop_limit: u8,
        treb_block_type: u64,
        custom_ingress_rego: Option<String>,
        custom_egress_rego: Option<String>,
        custom_routing_rego: Option<String>,
    ) -> Result<(), RegoRoutingError> {
        if !(1..=255).contains(&hop_limit) {
            return Err(RegoRoutingError::InvalidConfig(
                "hop_limit must be between 1 and 255".to_string(),
            ));
        }
        if !(192..=255).contains(&treb_block_type) {
            return Err(RegoRoutingError::InvalidConfig(
                "treb_block_type must reside in IANA experimental range 192..=255".to_string(),
            ));
        }

        let policy_dir = {
            let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
            guard.config.policy_dir.clone()
        };

        let base = PolicySources::from_dir_or_default(policy_dir.as_deref())?;
        let sources = base.with_all_overrides(
            custom_ingress_rego.as_deref(),
            custom_egress_rego.as_deref(),
            custom_routing_rego.as_deref(),
        )?;
        let compiled = PolicySuite::compile(sources)?;

        let (reconcile_notify, rib_notify) = {
            let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
            guard.config.active_profile = active_profile;
            guard.config.hop_limit = hop_limit;
            guard.config.treb_block_type = treb_block_type;
            guard.config.custom_ingress_rego = custom_ingress_rego;
            guard.config.custom_egress_rego = custom_egress_rego;
            guard.config.custom_routing_rego = custom_routing_rego;
            guard.suite = compiled;
            guard.bump_policy_version()
        };
        reconcile_notify.notify_one();
        rib_notify.notify_one();
        Ok(())
    }

    /// Evaluates the Ingress Rego policy for an arriving BPv7 bundle.
    ///
    /// When `commit_state` is `true` (classifier stage), accepted bundle IDs are
    /// recorded in the bounded `seen_cache` and initial Spray-and-Wait quotas are
    /// registered in `spray_tracker`.
    pub fn evaluate_ingress_bundle<'a>(
        &self,
        bundle: &Bundle,
        reader: &'a dyn Reader<'a>,
        metadata: &BundleMetadata,
        commit_state: bool,
    ) -> Result<RegoDecision, RegoRoutingError> {
        let (suite, config, blacklist_sources, seen_snapshot) = {
            let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
            let blacklist_sources: Vec<String> = guard
                .blacklist
                .iter()
                .filter(|b| b.enabled)
                .map(|b| b.eid_pattern.clone())
                .collect();
            (
                guard.suite.clone(),
                guard.config.clone(),
                blacklist_sources,
                guard.seen_cache.snapshot(),
            )
        };

        let canonical_id = canonical_bundle_key(bundle);
        let bundle_json = build_bundle_json(bundle, reader, metadata, config.treb_block_type, None);
        let input = serde_json::json!({
            "bundle": bundle_json,
            "node": {
                "local_eid": config.local_eid,
                "node_eids": config.node_eids,
                "callsign": config.callsign.as_deref().unwrap_or(""),
                "is_digipeater": config.is_digipeater,
                "supported_aliases": config.supported_aliases,
                "trapped_aliases": config.trapped_aliases,
                "hop_limit": config.hop_limit,
                "treb_block_type": config.treb_block_type,
                "record_treb": config.record_treb,
                "blacklist_sources": blacklist_sources,
                "seen_cache": seen_snapshot,
            },
            "current_dtn_time_ms": DtnTime::now().millisecs(),
            "ingress": {
                "cla_type": "bpa",
            }
        });

        let decision = suite.evaluate_ingress(&input)?;

        let should_audit = commit_state || decision.action == "DROP";
        if commit_state || should_audit {
            let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
            if commit_state && (decision.action == "ACCEPT" || decision.action == "DELIVER_LOCAL") {
                guard.seen_cache.insert(canonical_id.clone());
                if let Some(quota) = extract_spray_quota(bundle, reader) {
                    guard.spray_tracker.set(canonical_id.clone(), quota);
                }
            }
            if should_audit {
                push_audit_locked(
                    &mut guard,
                    "ingress",
                    &canonical_id,
                    &bundle.primary.id.source.to_string(),
                    &bundle.primary.destination.to_string(),
                    None,
                    &decision.action,
                    &decision.reason,
                    decision.route_key.clone(),
                );
            }
        }

        Ok(decision)
    }

    /// Reads the tracked remaining local Spray-and-Wait quota for `bundle`, if any.
    pub fn tracked_spray_quota(&self, bundle: &Bundle) -> Option<u32> {
        let key = canonical_bundle_key(bundle);
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        guard.spray_tracker.get(&key)
    }

    /// Seeds or updates the local Spray-and-Wait quota tracker for `bundle`.
    pub fn set_tracked_spray_quota(&self, bundle: &Bundle, quota: u32) {
        let key = canonical_bundle_key(bundle);
        let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
        guard.spray_tracker.set(key, quota);
    }

    /// Evaluates the Egress Rego policy before transmission toward `next_hop`.
    pub fn evaluate_egress_bundle<'a>(
        &self,
        bundle: &Bundle,
        reader: &'a dyn Reader<'a>,
        metadata: &BundleMetadata,
        next_hop: &Eid,
    ) -> Result<RegoDecision, RegoRoutingError> {
        let canonical_id = canonical_bundle_key(bundle);
        let (suite, config, tracked_quota) = {
            let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
            (
                guard.suite.clone(),
                guard.config.clone(),
                guard.spray_tracker.get(&canonical_id),
            )
        };

        let bundle_json = build_bundle_json(
            bundle,
            reader,
            metadata,
            config.treb_block_type,
            tracked_quota,
        );
        let input = serde_json::json!({
            "bundle": bundle_json,
            "node": {
                "local_eid": config.local_eid,
                "node_eids": config.node_eids,
                "callsign": config.callsign.as_deref().unwrap_or(""),
                "is_digipeater": config.is_digipeater,
                "supported_aliases": config.supported_aliases,
                "trapped_aliases": config.trapped_aliases,
                "hop_limit": config.hop_limit,
                "treb_block_type": config.treb_block_type,
                "record_treb": config.record_treb,
                "blacklist_sources": Vec::<String>::new(),
                "seen_cache": Vec::<String>::new(),
            },
            "current_dtn_time_ms": DtnTime::now().millisecs(),
            "contact": {
                "peer_eid": next_hop.to_string(),
                "cla_type": "bpa",
                "is_broadcast": false,
                "held_bundle_ids": Vec::<String>::new(),
            }
        });

        let decision = suite.evaluate_egress(&input)?;

        {
            let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
            for m in &decision.mutations {
                if m.operation == "MUTATE_SPRAY_QUOTA"
                    && let Some(local_q) = m.local_quota
                {
                    guard.spray_tracker.set(canonical_id.clone(), local_q);
                }
            }
            push_audit_locked(
                &mut guard,
                "egress",
                &canonical_id,
                &bundle.primary.id.source.to_string(),
                &bundle.primary.destination.to_string(),
                Some(next_hop.to_string()),
                &decision.action,
                &decision.reason,
                None,
            );
        }

        Ok(decision)
    }

    /// Returns recent Rego policy evaluation records ordered newest first.
    pub fn decision_log(&self) -> Vec<DecisionAuditEntry> {
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        guard.decision_log.iter().cloned().collect()
    }

    /// Clears the in-memory decision audit ring buffer.
    pub fn clear_decision_log(&self) {
        let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
        guard.decision_log.clear();
    }
}

impl dtnpm_core::cla_observer::PeerObserver for RegoRoutingEngine {
    fn on_peer_up(&self, cla_name: &str, cla_type: &str, addr: &ClaAddress, node_ids: &[NodeId]) {
        let peer_eids: Vec<String> = node_ids
            .iter()
            .map(|nid| Eid::from(nid.clone()).to_string())
            .collect();
        self.upsert_peers(cla_name, cla_type, &addr.to_string(), peer_eids);
    }

    fn on_peer_down(&self, cla_name: &str, addr: &ClaAddress) {
        self.remove_peers(cla_name, &addr.to_string());
    }
}

#[allow(clippy::too_many_arguments)]
fn push_audit_locked(
    state: &mut RegoRoutingState,
    phase: &str,
    bundle_id: &str,
    source: &str,
    destination: &str,
    peer_eid: Option<String>,
    action: &str,
    reason: &str,
    route_key: Option<String>,
) {
    let cap = state.config.max_audit_entries.max(10);
    while state.decision_log.len() >= cap {
        state.decision_log.pop_back();
    }
    let id = state.next_audit_id;
    state.next_audit_id = state.next_audit_id.saturating_add(1);
    state.decision_log.push_front(DecisionAuditEntry {
        id,
        timestamp: OffsetDateTime::now_utc().unix_timestamp(),
        phase: phase.to_string(),
        bundle_id: bundle_id.to_string(),
        source: source.to_string(),
        destination: destination.to_string(),
        peer_eid,
        action: action.to_string(),
        reason: reason.to_string(),
        route_key,
    });
}

/// Builds canonical deduplication identifier `<source>@<time>#<seq>`.
pub fn canonical_bundle_key(bundle: &Bundle) -> String {
    let time_ms = bundle
        .primary
        .id
        .timestamp
        .creation_time()
        .map_or(0, |t| t.millisecs());
    let seq = bundle.primary.id.timestamp.sequence_number();
    format!("{}@{time_ms}#{seq}", bundle.primary.id.source)
}

fn read_block_bytes<'a>(reader: &'a dyn Reader<'a>, block_num: u64) -> Option<Vec<u8>> {
    let (_, avail) = reader.block(block_num)?;
    let payload = avail.available()?;
    Some(payload.as_ref().to_vec())
}

fn extract_spray_quota<'a>(bundle: &Bundle, reader: &'a dyn Reader<'a>) -> Option<u32> {
    let mut block_nums: BTreeSet<u64> = bundle.blocks.keys().copied().collect();
    block_nums.remove(&0);
    block_nums.remove(&1);

    for bn in block_nums {
        let Some(blk) = bundle.blocks.get(&bn) else {
            continue;
        };
        let btype = u64::from(blk.block_type);
        if btype == BLOCK_TYPE_MESH_ROUTING
            && let Some(bytes) = read_block_bytes(reader, bn)
            && let Ok(mesh) = MeshRoutingData::decode_cbor(&bytes)
            && let Some(rep) = mesh.replication_control
        {
            return Some(rep.quota);
        }
        if btype == BLOCK_TYPE_SPRAY_PERMIT
            && let Some(bytes) = read_block_bytes(reader, bn)
            && let Ok(q) = decode_spray_permit(&bytes)
        {
            return Some(q);
        }
    }
    None
}

/// Converts a live Hardy [`Bundle`], its readable extension blocks, and [`BundleMetadata`]
/// into the structured `input.bundle` JSON document expected by OPA/Rego policies.
pub fn build_bundle_json<'a>(
    bundle: &Bundle,
    reader: &'a dyn Reader<'a>,
    metadata: &BundleMetadata,
    treb_block_type: u64,
    tracked_spray_quota: Option<u32>,
) -> serde_json::Value {
    let creation_time = bundle
        .primary
        .id
        .timestamp
        .creation_time()
        .map_or(0, |t| t.millisecs());
    let sequence_number = bundle.primary.id.timestamp.sequence_number();
    let lifetime_ms = u64::try_from(bundle.primary.lifetime.as_millis()).unwrap_or(u64::MAX);

    let block_nums: BTreeSet<u64> = bundle.blocks.keys().copied().collect();
    let mut extension_blocks = Vec::new();

    for bn in block_nums {
        let Some(blk) = bundle.blocks.get(&bn) else {
            continue;
        };
        if matches!(blk.block_type, block::Type::Primary | block::Type::Payload) {
            continue;
        }
        let btype = u64::from(blk.block_type);
        match btype {
            BLOCK_TYPE_PREVIOUS_NODE => {
                let prev = reader
                    .extract::<Eid>(bn)
                    .ok()
                    .flatten()
                    .map(|e| e.to_string())
                    .or_else(|| {
                        metadata
                            .extensions
                            .previous_node
                            .as_ref()
                            .map(ToString::to_string)
                    });
                if let Some(eid_str) = prev {
                    extension_blocks.push(serde_json::json!({
                        "block_type": BLOCK_TYPE_PREVIOUS_NODE,
                        "block_number": bn,
                        "previous_node_eid": eid_str,
                    }));
                }
            }
            BLOCK_TYPE_BUNDLE_AGE => {
                let age_ms = reader
                    .extract::<BundleAge>(bn)
                    .ok()
                    .flatten()
                    .map(u64::from)
                    .or_else(|| {
                        metadata
                            .extensions
                            .age
                            .and_then(|d| u64::try_from(d.as_millis()).ok())
                    })
                    .unwrap_or(0);
                extension_blocks.push(serde_json::json!({
                    "block_type": BLOCK_TYPE_BUNDLE_AGE,
                    "block_number": bn,
                    "age_ms": age_ms,
                }));
            }
            BLOCK_TYPE_HOP_COUNT => {
                let hop = reader
                    .extract::<HopInfo>(bn)
                    .ok()
                    .flatten()
                    .or(metadata.extensions.hop_count);
                if let Some(h) = hop {
                    extension_blocks.push(serde_json::json!({
                        "block_type": BLOCK_TYPE_HOP_COUNT,
                        "block_number": bn,
                        "hop_limit": h.limit.get(),
                        "hop_count": h.count,
                    }));
                }
            }
            BLOCK_TYPE_SPRAY_PERMIT => {
                if let Some(bytes) = read_block_bytes(reader, bn) {
                    match decode_spray_permit(&bytes) {
                        Ok(wire_quota) => {
                            let effective_quota = tracked_spray_quota.unwrap_or(wire_quota);
                            extension_blocks.push(serde_json::json!({
                                "block_type": BLOCK_TYPE_SPRAY_PERMIT,
                                "block_number": bn,
                                "payload": { "quota": effective_quota, "wire_quota": wire_quota },
                            }));
                        }
                        Err(e) => {
                            warn!("Failed to decode Spray Permit block {bn}: {e}");
                        }
                    }
                }
            }
            BLOCK_TYPE_MESH_ROUTING => {
                if let Some(bytes) = read_block_bytes(reader, bn) {
                    match MeshRoutingData::decode_cbor(&bytes) {
                        Ok(mut data) => {
                            if let (Some(tracked), Some(rep)) =
                                (tracked_spray_quota, data.replication_control.as_mut())
                            {
                                rep.quota = tracked;
                            }
                            extension_blocks.push(serde_json::json!({
                                "block_type": BLOCK_TYPE_MESH_ROUTING,
                                "block_number": bn,
                                "payload": data,
                            }));
                        }
                        Err(e) => {
                            warn!("Failed to decode Mesh Routing block {bn}: {e}");
                        }
                    }
                }
            }
            t if t == treb_block_type => {
                if let Some(bytes) = read_block_bytes(reader, bn) {
                    match TrebData::decode_cbor(&bytes) {
                        Ok(treb) => {
                            extension_blocks.push(serde_json::json!({
                                "block_type": t,
                                "block_number": bn,
                                "payload": treb,
                            }));
                        }
                        Err(e) => {
                            warn!("Failed to decode TREB block {bn} (type {t}): {e}");
                        }
                    }
                }
            }
            other_type => {
                if let Some(bytes) = read_block_bytes(reader, bn) {
                    let payload = match decode_cbor_to_json(&bytes) {
                        Ok(val) => val,
                        Err(_) => serde_json::json!({ "raw_len": bytes.len() }),
                    };
                    extension_blocks.push(serde_json::json!({
                        "block_type": other_type,
                        "block_number": bn,
                        "payload": payload,
                    }));
                }
            }
        }
    }

    serde_json::json!({
        "primary": {
            "source": bundle.primary.id.source.to_string(),
            "destination": bundle.primary.destination.to_string(),
            "report_to": bundle.primary.report_to.to_string(),
            "creation_timestamp": {
                "time": creation_time,
                "sequence_number": sequence_number,
            },
            "lifetime": lifetime_ms,
            "processing_flags": {
                "delete_report_requested": bundle.primary.flags.delete_report_requested,
                "is_fragment": bundle.primary.flags.is_fragment,
                "is_admin_record": bundle.primary.flags.is_admin_record,
            },
        },
        "extension_blocks": extension_blocks,
    })
}

fn build_routing_node_json(
    config: &RegoRoutingConfig,
    blacklist_sources: &[String],
) -> serde_json::Value {
    serde_json::json!({
        "local_eid": config.local_eid,
        "node_eids": config.node_eids,
        "callsign": config.callsign.as_deref().unwrap_or(""),
        "is_digipeater": config.is_digipeater,
        "supported_aliases": config.supported_aliases,
        "trapped_aliases": config.trapped_aliases,
        "hop_limit": config.hop_limit,
        "treb_block_type": config.treb_block_type,
        "record_treb": config.record_treb,
        "blacklist_sources": blacklist_sources,
    })
}
