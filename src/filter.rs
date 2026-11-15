//! Hardy BPA [`FilterPack`] adapters executing OPA/Rego policies at Ingress
//! (`Verifier` + `Classifier`) and Egress (`Rewriter`).

use std::sync::Arc;

use hardy_bpa::filter::{
    Boundary, Classifier, ClassifyContext, RewriteContext, Rewriter, Verdict, Verifier,
    VerifyContext, pack::FilterPack, slots::MetadataDelta,
};
use hardy_bpv7::{block, crc, eid::Eid, status_report::ReasonCode};
use tracing::{debug, warn};

use crate::blocks::{
    BLOCK_TYPE_MESH_ROUTING, BLOCK_TYPE_SPRAY_PERMIT, MeshRoutingData, PathElement, PolicyMutation,
    StagedBundleDecision, TrebData, TrebHopEntry, encode_spray_permit,
};
use crate::engine::{RegoRoutingEngine, canonical_bundle_key};
use crate::policy::RegoDecision;

hardy_bpa::slot!(pub static REGO_BUNDLE_DECISION: StagedBundleDecision);

/// Ingress verifier enforcing fail-closed Rego drops (blacklist, Hop Count Type 10,
/// expired lifetime, storm prevention / duplicate & APRS loop guard).
#[derive(Clone)]
pub struct RegoIngressVerifier {
    engine: Arc<RegoRoutingEngine>,
}

impl RegoIngressVerifier {
    pub fn new(engine: Arc<RegoRoutingEngine>) -> Self {
        Self { engine }
    }
}

impl Verifier for RegoIngressVerifier {
    fn verify(&self, ctx: &VerifyContext<'_>) -> Verdict {
        match self
            .engine
            .evaluate_ingress_bundle(ctx.bundle(), ctx.reader(), ctx.metadata(), false)
        {
            Ok(decision) => decision_to_drop_verdict(&decision).unwrap_or(Verdict::Continue(())),
            Err(err) => {
                warn!("Rego ingress verifier error (fail-closed drop): {err}");
                Verdict::Drop(None)
            }
        }
    }
}

/// Ingress classifier committing deduplication state, Spray-and-Wait tracking,
/// staged extension mutations, and dynamic `route_key` overrides into Hardy slots.
#[derive(Clone)]
pub struct RegoIngressClassifier {
    engine: Arc<RegoRoutingEngine>,
}

impl RegoIngressClassifier {
    pub fn new(engine: Arc<RegoRoutingEngine>) -> Self {
        Self { engine }
    }
}

impl Classifier for RegoIngressClassifier {
    fn classify(&self, ctx: &ClassifyContext<'_>) -> Verdict<MetadataDelta> {
        let decision = match self.engine.evaluate_ingress_bundle(
            ctx.bundle(),
            ctx.reader(),
            ctx.metadata(),
            true,
        ) {
            Ok(d) => d,
            Err(err) => {
                warn!("Rego ingress classifier error (fail-closed drop): {err}");
                return Verdict::Drop(None);
            }
        };

        if let Some(Verdict::Drop(reason)) = decision_to_drop_verdict::<MetadataDelta>(&decision) {
            return Verdict::Drop(reason);
        }

        let staged = StagedBundleDecision {
            policy_action: decision.action.clone(),
            reason: Some(decision.reason.clone()),
            reason_code: decision.reason_code,
            generate_status_report: decision.generate_status_report,
            ingress_mutations: decision.mutations.clone(),
            selected_route_key: decision.route_key.clone(),
            spray_quota: None,
            spray_mode: None,
        };

        let mut delta = MetadataDelta::default();
        delta.set(&REGO_BUNDLE_DECISION, &staged);

        if let Some(rk) = &decision.route_key {
            match rk.parse::<Eid>() {
                Ok(eid) => {
                    delta.route_key = Some(eid);
                }
                Err(err) => {
                    debug!("Ignoring non-EID route_key '{rk}': {err}");
                }
            }
        }

        Verdict::Continue(delta)
    }
}

/// Egress rewriter executing Rego egress rules (Spray-and-Wait quota splitting,
/// APRS future path consumption, and TREB past path hop recording).
#[derive(Clone)]
pub struct RegoEgressRewriter {
    engine: Arc<RegoRoutingEngine>,
}

impl RegoEgressRewriter {
    pub fn new(engine: Arc<RegoRoutingEngine>) -> Self {
        Self { engine }
    }
}

impl Rewriter for RegoEgressRewriter {
    fn rewrite(&self, ctx: &mut RewriteContext<'_>) {
        let Boundary::Egress { next_hop } = ctx.boundary() else {
            return;
        };
        let next_hop_eid = next_hop.clone();

        let staged = ctx.metadata().slot(&REGO_BUNDLE_DECISION);
        let egress_decision = match self.engine.evaluate_egress_bundle(
            ctx.bundle(),
            ctx.reader(),
            ctx.metadata(),
            &next_hop_eid,
        ) {
            Ok(d) => d,
            Err(err) => {
                warn!("Rego egress rewriter evaluation failed: {err}");
                return;
            }
        };

        let mut all_mutations = staged.map(|s| s.ingress_mutations).unwrap_or_default();
        all_mutations.extend(egress_decision.mutations);

        if all_mutations.is_empty() {
            return;
        }

        let treb_block_type = self.engine.config().treb_block_type;
        let mut treb_entries: Vec<TrebHopEntry> = Vec::new();
        for mutation in &all_mutations {
            if mutation.operation == "APPEND_TREB_HOP"
                || mutation.operation == "APPEND_TREB_DEPARTURE"
            {
                if let Some(val) = &mutation.value
                    && let Ok(entry) = serde_json::from_value::<TrebHopEntry>(val.clone())
                {
                    treb_entries.push(entry);
                }
            } else {
                apply_mutation(ctx, &self.engine, mutation);
            }
        }
        if !treb_entries.is_empty() {
            apply_treb_entries(ctx, treb_block_type, treb_entries);
        }
    }
}

/// Constructs Hardy's unified [`FilterPack`] wiring the Rego Verifier, Classifier,
/// and Egress Rewriter into Hardy's BPA pipeline.
pub fn build_filter_pack(engine: Arc<RegoRoutingEngine>) -> FilterPack {
    let mut pack = FilterPack::new("dtnpm-rego-routing");
    pack.ingress_verifier(
        "rego-ingress-verifier",
        RegoIngressVerifier::new(engine.clone()),
    )
    .ingress_classifier(
        "rego-ingress-classifier",
        RegoIngressClassifier::new(engine.clone()),
    )
    .egress_rewriter("rego-egress-rewriter", RegoEgressRewriter::new(engine));
    pack
}

fn decision_to_drop_verdict<T>(decision: &RegoDecision) -> Option<Verdict<T>> {
    if decision.action != "DROP" {
        return None;
    }
    if !decision.generate_status_report {
        return Some(Verdict::Drop(None));
    }
    let reason = decision
        .reason_code
        .and_then(|c| ReasonCode::try_from(c).ok())
        .or(Some(ReasonCode::NoAdditionalInformation));
    Some(Verdict::Drop(reason))
}

fn find_block_by_type(ctx: &RewriteContext<'_>, target_type: u64) -> Option<(u64, Vec<u8>)> {
    let mut block_nums: Vec<u64> = ctx.bundle().blocks.keys().copied().collect();
    block_nums.sort_unstable();
    for bn in block_nums {
        let Some(blk) = ctx.bundle().blocks.get(&bn) else {
            continue;
        };
        if u64::from(blk.block_type) == target_type
            && let Some((_, avail)) = ctx.reader().block(bn)
            && let Some(payload) = avail.available()
        {
            return Some((bn, payload.as_ref().to_vec()));
        }
    }
    None
}

fn apply_mutation(
    ctx: &mut RewriteContext<'_>,
    engine: &RegoRoutingEngine,
    mutation: &PolicyMutation,
) {
    match mutation.operation.as_str() {
        "SET_FIELD" => {
            // Hop Count Block (Type 10) is incremented by Hardy BPA's update_extension_blocks
            // immediately after egress rewriters run; avoid double-incrementing here.
            debug!(
                "Logged SET_FIELD mutation on block {} ({:?})",
                mutation.block_type, mutation.field
            );
        }
        "MUTATE_SPRAY_QUOTA" => apply_spray_quota_mutation(ctx, engine, mutation),
        "MUTATE_APRS_ALIAS" | "MUTATE_APRS_STRICT" => apply_aprs_mutation(ctx, mutation),
        other => {
            debug!("Ignoring unknown Rego mutation operation '{other}'");
        }
    }
}

fn apply_spray_quota_mutation(
    ctx: &mut RewriteContext<'_>,
    engine: &RegoRoutingEngine,
    mutation: &PolicyMutation,
) {
    let Some(tx_quota) = mutation.transmitted_quota else {
        return;
    };

    if let Some((bn, bytes)) = find_block_by_type(ctx, BLOCK_TYPE_MESH_ROUTING) {
        match MeshRoutingData::decode_cbor(&bytes) {
            Ok(mut mesh) => {
                if let Some(rep) = mesh.replication_control.as_mut() {
                    rep.quota = tx_quota;
                    if let Some(phase) = mutation.transmitted_phase {
                        rep.phase = Some(phase);
                    }
                    match mesh.encode_cbor() {
                        Ok(encoded) => {
                            if let Err(err) = ctx.editor().replace(bn, encoded) {
                                warn!("Failed to rewrite Mesh Block {bn} spray quota: {err}");
                            }
                        }
                        Err(err) => warn!("Failed to re-encode Mesh Block {bn}: {err}"),
                    }
                }
            }
            Err(err) => warn!("Failed to decode Mesh Block {bn} during spray mutation: {err}"),
        }
    } else if let Some((bn, _bytes)) = find_block_by_type(ctx, BLOCK_TYPE_SPRAY_PERMIT) {
        let encoded = encode_spray_permit(tx_quota);
        if let Err(err) = ctx.editor().replace(bn, encoded) {
            warn!("Failed to rewrite Spray Permit Block {bn}: {err}");
        }
    }

    if let Some(local_quota) = mutation.local_quota {
        let key = canonical_bundle_key(ctx.bundle());
        let _ = key;
        engine.set_tracked_spray_quota(ctx.bundle(), local_quota);
    }
}

fn apply_aprs_mutation(ctx: &mut RewriteContext<'_>, mutation: &PolicyMutation) {
    let Some((bn, bytes)) = find_block_by_type(ctx, BLOCK_TYPE_MESH_ROUTING) else {
        return;
    };
    let Ok(mut mesh) = MeshRoutingData::decode_cbor(&bytes) else {
        warn!("Failed to decode Mesh Block {bn} for APRS mutation");
        return;
    };
    let Some(traj) = mesh.trajectory_control.as_mut() else {
        return;
    };
    let idx = traj.active_hop_index as usize;
    let Some(elem) = traj.path_elements.get_mut(idx) else {
        return;
    };

    let actor_id = mutation
        .value
        .as_ref()
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let mut advance = false;
    match (mutation.operation.as_str(), elem) {
        ("MUTATE_APRS_ALIAS", PathElement::Alias(alias)) => {
            alias.remaining_count = alias.remaining_count.saturating_sub(1);
            if !actor_id.is_empty() {
                alias.serviced_by = Some(actor_id);
            }
            if alias.remaining_count == 0 {
                alias.completed = true;
                advance = true;
            }
        }
        ("MUTATE_APRS_STRICT", PathElement::Strict(strict)) => {
            strict.completed = true;
            advance = true;
        }
        _ => {}
    }

    if advance {
        traj.active_hop_index = traj.active_hop_index.saturating_add(1);
    }

    match mesh.encode_cbor() {
        Ok(encoded) => {
            if let Err(err) = ctx.editor().replace(bn, encoded) {
                warn!("Failed to rewrite Mesh Block {bn} APRS path: {err}");
            }
        }
        Err(err) => warn!("Failed to encode mutated APRS Mesh Block {bn}: {err}"),
    }
}

fn apply_treb_entries(
    ctx: &mut RewriteContext<'_>,
    treb_block_type: u64,
    entries: Vec<TrebHopEntry>,
) {
    let existing = find_block_by_type(ctx, treb_block_type);
    let mut treb = match &existing {
        Some((_, bytes)) => TrebData::decode_cbor(bytes).unwrap_or_default(),
        None => TrebData::default(),
    };

    for entry in entries {
        // Merge ingress arrival + egress departure into one hop record per node when applicable.
        if let Some(last) = treb.hops.last_mut()
            && last.node_eid == entry.node_eid
            && last.departure_time_ms.is_none()
            && entry.departure_time_ms.is_some()
        {
            last.departure_time_ms = entry.departure_time_ms;
            if entry.cla_info.is_some() {
                last.cla_info = entry.cla_info;
            }
        } else {
            treb.push_hop(entry);
        }
    }

    let Ok(encoded) = treb.encode_cbor() else {
        warn!("Failed to encode updated TREB block");
        return;
    };

    match existing {
        Some((bn, _)) => {
            if let Err(err) = ctx.editor().replace(bn, encoded) {
                warn!("Failed to replace TREB block {bn}: {err}");
            }
        }
        None => {
            let flags = block::Flags {
                report_on_failure: !ctx.bundle().primary.flags.is_admin_record,
                must_replicate: true,
                ..Default::default()
            };
            if let Err(err) = ctx.editor().insert(
                block::Type::Unrecognised(treb_block_type),
                flags,
                crc::CrcType::None,
                encoded,
            ) {
                warn!("Failed to insert TREB block type {treb_block_type}: {err}");
            }
        }
    }
}
