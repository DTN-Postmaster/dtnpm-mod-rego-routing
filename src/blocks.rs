//! BPv7 extension block codecs and arbitrary CBOR inspection helpers.
//!
//! Pure wire codecs are shared via [`dtnpm_core::mesh_blocks`]; this module
//! re-exports them alongside FilterPack-specific staging structs.

use hardy_cbor::{
    decode::FromCbor,
    encode::{Encoder, ToCbor},
};
use serde::{Deserialize, Serialize};

pub use dtnpm_core::mesh_blocks::{
    BLOCK_TYPE_BUNDLE_AGE, BLOCK_TYPE_HOP_COUNT, BLOCK_TYPE_MESH_ROUTING, BLOCK_TYPE_PREVIOUS_NODE,
    BLOCK_TYPE_SPRAY_PERMIT, DEFAULT_BLOCK_TYPE_TREB, LegacyBridgeId, MeshBlockError,
    MeshRoutingData, PathElement, ReplicationControl, ScopedAlias, SpatialScope, StrictTarget,
    TrajectoryControl, TrebData, TrebHopEntry, decode_cbor_to_json, decode_spray_permit,
    encode_spray_permit, format_aprs_path, parse_aprs_path,
};

use crate::error::RegoRoutingError;

/// Mutation directive emitted by OPA/Rego policies and executed at Egress or delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMutation {
    #[serde(default)]
    pub block_type: u64,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_quota: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_phase: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transmitted_quota: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transmitted_phase: Option<u8>,
}

/// Bundle-scoped Rego ingress evaluation staged into Hardy BPA metadata slot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedBundleDecision {
    pub policy_action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<u64>,
    #[serde(default)]
    pub generate_status_report: bool,
    #[serde(default)]
    pub ingress_mutations: Vec<PolicyMutation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_route_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spray_quota: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spray_mode: Option<u8>,
}

impl ToCbor for StagedBundleDecision {
    type Result = ();

    fn to_cbor(&self, encoder: &mut Encoder) -> Self::Result {
        let serialized = serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string());
        encoder.emit(&serialized);
    }
}

impl FromCbor for StagedBundleDecision {
    type Error = RegoRoutingError;

    fn from_cbor(data: &[u8]) -> Result<(Self, bool, usize), Self::Error> {
        let (json_str, shortest, len) = String::from_cbor(data)?;
        let decoded = serde_json::from_str(&json_str)?;
        Ok((decoded, shortest, len))
    }
}
