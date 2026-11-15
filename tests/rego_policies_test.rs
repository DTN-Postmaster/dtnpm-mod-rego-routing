//! Unit tests for OPA/Rego routing policies, CBOR extension block codecs,
//! blacklist matching, RFC 9171 §4.3.3 Hop Count, Spray-and-Wait, APRS, and TREB.

use std::collections::BTreeMap;

use dtnpm_mod_rego_routing::blocks::{
    LegacyBridgeId, MeshRoutingData, PathElement, ReplicationControl, ScopedAlias, StrictTarget,
    TrajectoryControl, TrebData, TrebHopEntry, decode_cbor_to_json, decode_spray_permit,
    encode_spray_permit,
};
use dtnpm_mod_rego_routing::policy::{PolicySources, PolicySuite};

fn base_node() -> serde_json::Value {
    serde_json::json!({
        "local_eid": "dtn://node-b/",
        "node_eids": ["dtn://node-b/", "F4XYZ-1"],
        "callsign": "F4XYZ-1",
        "is_digipeater": true,
        "supported_aliases": ["WIDE1", "WIDE2"],
        "trapped_aliases": ["WIDE3", "WIDE4"],
        "hop_limit": 16,
        "treb_block_type": 201,
        "record_treb": false,
        "blacklist_sources": [],
        "seen_cache": [],
    })
}

fn base_bundle(source: &str, dest: &str, ext_blocks: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "primary": {
            "source": source,
            "destination": dest,
            "report_to": source,
            "creation_timestamp": {
                "time": 1000,
                "sequence_number": 1,
            },
            "lifetime": 60_000,
            "processing_flags": {
                "delete_report_requested": true,
                "is_fragment": false,
                "is_admin_record": false,
            }
        },
        "extension_blocks": ext_blocks,
    })
}

#[test]
fn embedded_policies_compile_cleanly() {
    PolicySuite::compile(PolicySources::default()).expect("default Rego policies must compile");
}

#[test]
fn ingress_blacklist_exact_and_wildcard_drop_silently() {
    let suite = PolicySuite::compile(PolicySources::default()).expect("compile");
    let mut node = base_node();
    node["blacklist_sources"] = serde_json::json!(["dtn://evil/app", "dtn://spam/*", "ipn:99.*"]);

    for bad_src in ["dtn://evil/app", "dtn://spam/beacon", "ipn:99.42"] {
        let input = serde_json::json!({
            "bundle": base_bundle(bad_src, "dtn://node-b/", vec![]),
            "node": node,
            "current_dtn_time_ms": 2000,
            "ingress": { "cla_type": "tcpcl" }
        });
        let dec = suite.evaluate_ingress(&input).expect("eval");
        assert_eq!(dec.action, "DROP", "source {bad_src} must be dropped");
        assert!(
            !dec.generate_status_report,
            "blacklisted source must drop silently without status report"
        );
    }

    let ok_input = serde_json::json!({
        "bundle": base_bundle("dtn://friend/app", "dtn://node-c/", vec![]),
        "node": node,
        "current_dtn_time_ms": 2000,
        "ingress": { "cla_type": "tcpcl" }
    });
    let ok_dec = suite.evaluate_ingress(&ok_input).expect("eval");
    assert_eq!(ok_dec.action, "ACCEPT");
}

#[test]
fn hop_count_block_rfc9171_and_local_delivery_priority() {
    let suite = PolicySuite::compile(PolicySources::default()).expect("compile");
    let node = base_node();

    // Transit bundle with hop_count=4, hop_limit=5 -> (4+1)>=5 -> DROP (reason_code 9)
    let drop_input = serde_json::json!({
        "bundle": base_bundle("dtn://src/1", "dtn://remote/1", vec![
            serde_json::json!({ "block_type": 10, "hop_count": 4, "hop_limit": 5 })
        ]),
        "node": node,
        "current_dtn_time_ms": 2000,
    });
    let drop_dec = suite.evaluate_ingress(&drop_input).expect("eval");
    assert_eq!(drop_dec.action, "DROP");
    assert_eq!(drop_dec.reason_code, Some(9));
    assert!(drop_dec.generate_status_report);

    // Local destination with hop_count=5, hop_limit=5 -> DELIVER_LOCAL takes priority (RFC 9171 §5.3 Step 1)
    let local_input = serde_json::json!({
        "bundle": base_bundle("dtn://src/1", "dtn://node-b/", vec![
            serde_json::json!({ "block_type": 10, "hop_count": 5, "hop_limit": 5 })
        ]),
        "node": node,
        "current_dtn_time_ms": 2000,
    });
    let local_dec = suite.evaluate_ingress(&local_input).expect("eval");
    assert_eq!(local_dec.action, "DELIVER_LOCAL");

    // Transit bundle with hop_count=2, hop_limit=5 -> ACCEPT + SET_FIELD hop_count=3
    let accept_input = serde_json::json!({
        "bundle": base_bundle("dtn://src/1", "dtn://remote/1", vec![
            serde_json::json!({ "block_type": 10, "hop_count": 2, "hop_limit": 5 })
        ]),
        "node": node,
        "current_dtn_time_ms": 2000,
    });
    let accept_dec = suite.evaluate_ingress(&accept_input).expect("eval");
    assert_eq!(accept_dec.action, "ACCEPT");
    assert_eq!(accept_dec.mutations.len(), 1);
    assert_eq!(accept_dec.mutations[0].operation, "SET_FIELD");
    assert_eq!(accept_dec.mutations[0].value, Some(serde_json::json!(3)));
}

#[test]
fn storm_prevention_rejects_duplicate_bundle() {
    let suite = PolicySuite::compile(PolicySources::default()).expect("compile");
    let mut node = base_node();
    node["seen_cache"] = serde_json::json!(["dtn://src/1@1000#1"]);

    let dup_input = serde_json::json!({
        "bundle": base_bundle("dtn://src/1", "dtn://remote/1", vec![]),
        "node": node,
        "current_dtn_time_ms": 2000,
    });
    let dec = suite.evaluate_ingress(&dup_input).expect("eval");
    assert_eq!(dec.action, "DROP");
}

#[test]
fn spray_and_wait_type_200_and_type_194_egress_splitting() {
    let suite = PolicySuite::compile(PolicySources::default()).expect("compile");
    let node = base_node();

    // Binary Spray on Block 200 (L=6 -> tx=3, keep=3)
    let binary_input = serde_json::json!({
        "bundle": base_bundle("dtn://src/1", "dtn://dest/1", vec![
            serde_json::json!({
                "block_type": 200,
                "payload": {
                    "replication_control": { "quota": 6, "mode": 2, "phase": 1 }
                }
            })
        ]),
        "node": node,
        "current_dtn_time_ms": 2000,
        "contact": { "peer_eid": "dtn://relay-c/", "cla_type": "tcpcl", "is_broadcast": false }
    });
    let bin_dec = suite.evaluate_egress(&binary_input).expect("eval");
    assert_eq!(bin_dec.action, "FORWARD_REPLICATE");
    assert_eq!(bin_dec.mutations[0].operation, "MUTATE_SPRAY_QUOTA");
    assert_eq!(bin_dec.mutations[0].block_type, 200);
    assert_eq!(bin_dec.mutations[0].transmitted_quota, Some(3));
    assert_eq!(bin_dec.mutations[0].local_quota, Some(3));

    // Binary Spray on Block 194 (L=4 -> tx=2, keep=2)
    let b194_input = serde_json::json!({
        "bundle": base_bundle("dtn://src/1", "dtn://dest/1", vec![
            serde_json::json!({ "block_type": 194, "payload": { "quota": 4 } })
        ]),
        "node": node,
        "current_dtn_time_ms": 2000,
        "contact": { "peer_eid": "dtn://relay-c/", "cla_type": "tcpcl", "is_broadcast": false }
    });
    let b194_dec = suite.evaluate_egress(&b194_input).expect("eval");
    assert_eq!(b194_dec.action, "FORWARD_REPLICATE");
    assert_eq!(b194_dec.mutations[0].block_type, 194);
    assert_eq!(b194_dec.mutations[0].transmitted_quota, Some(2));
    assert_eq!(b194_dec.mutations[0].local_quota, Some(2));

    // WAIT phase (L=1) -> SKIP for relay, FORWARD_DIRECT for destination
    let wait_relay = serde_json::json!({
        "bundle": base_bundle("dtn://src/1", "dtn://dest/1", vec![
            serde_json::json!({ "block_type": 194, "payload": { "quota": 1 } })
        ]),
        "node": node,
        "current_dtn_time_ms": 2000,
        "contact": { "peer_eid": "dtn://relay-c/", "cla_type": "tcpcl", "is_broadcast": false }
    });
    assert_eq!(
        suite.evaluate_egress(&wait_relay).expect("eval").action,
        "SKIP"
    );

    let wait_dest = serde_json::json!({
        "bundle": base_bundle("dtn://src/1", "dtn://dest/1", vec![
            serde_json::json!({ "block_type": 194, "payload": { "quota": 1 } })
        ]),
        "node": node,
        "current_dtn_time_ms": 2000,
        "contact": { "peer_eid": "dtn://dest/1", "cla_type": "tcpcl", "is_broadcast": false }
    });
    assert_eq!(
        suite.evaluate_egress(&wait_dest).expect("eval").action,
        "FORWARD_DIRECT"
    );
}

#[test]
fn aprs_trajectory_and_treb_past_path_loop_prevention() {
    let suite = PolicySuite::compile(PolicySources::default()).expect("compile");
    let mut node = base_node();
    node["record_treb"] = serde_json::json!(true);

    // Valid WIDE1-1 alias hop + no loop in TREB -> ACCEPT with MUTATE_APRS_ALIAS & APPEND_TREB_HOP
    let aprs_input = serde_json::json!({
        "bundle": base_bundle("dtn://f4abc/aprs", "dtn://aprs-igate/", vec![
            serde_json::json!({
                "block_type": 200,
                "payload": {
                    "trajectory_control": {
                        "active_hop_index": 0,
                        "path_elements": [
                            { "target_type": 2, "scope_name": "WIDE1", "max_count": 1, "remaining_count": 1, "completed": false },
                            { "target_type": 1, "target_id": "dtn://aprs-igate/", "completed": false }
                        ]
                    }
                }
            })
        ]),
        "node": node,
        "current_dtn_time_ms": 5000,
    });
    let dec = suite.evaluate_ingress(&aprs_input).expect("eval");
    assert_eq!(dec.action, "ACCEPT");
    assert_eq!(dec.route_key.as_deref(), Some("dtn://aprs-igate/"));
    assert!(
        dec.mutations
            .iter()
            .any(|m| m.operation == "MUTATE_APRS_ALIAS")
    );
    assert!(
        dec.mutations
            .iter()
            .any(|m| m.operation == "APPEND_TREB_HOP")
    );

    // Trapped alias WIDE3 -> DROP
    let trapped_input = serde_json::json!({
        "bundle": base_bundle("dtn://f4abc/aprs", "dtn://aprs-igate/", vec![
            serde_json::json!({
                "block_type": 200,
                "payload": {
                    "trajectory_control": {
                        "active_hop_index": 0,
                        "path_elements": [
                            { "target_type": 2, "scope_name": "WIDE3", "max_count": 3, "remaining_count": 3, "completed": false }
                        ]
                    }
                }
            })
        ]),
        "node": node,
        "current_dtn_time_ms": 5000,
    });
    assert_eq!(
        suite.evaluate_ingress(&trapped_input).expect("eval").action,
        "DROP"
    );

    // TREB loop detection: local node already in TREB hops -> DROP
    let loop_input = serde_json::json!({
        "bundle": base_bundle("dtn://f4abc/aprs", "dtn://aprs-igate/", vec![
            serde_json::json!({
                "block_type": 201,
                "payload": {
                    "hops": [{ "node_eid": "dtn://node-b/", "arrival_time_ms": 4000 }]
                }
            })
        ]),
        "node": node,
        "current_dtn_time_ms": 5000,
    });
    assert_eq!(
        suite.evaluate_ingress(&loop_input).expect("eval").action,
        "DROP"
    );
}

#[test]
fn cbor_codecs_and_custom_extension_block_policy() {
    // 1. Block 200 roundtrip
    let mut custom_attrs = BTreeMap::new();
    custom_attrs.insert("priority".to_string(), serde_json::json!("emergency"));
    let mesh = MeshRoutingData {
        legacy_bridge_id: Some(LegacyBridgeId::Uint(42)),
        replication_control: Some(ReplicationControl {
            quota: 8,
            mode: Some(2),
            phase: Some(1),
            generation: Some(1),
        }),
        trajectory_control: Some(TrajectoryControl {
            path_elements: vec![
                PathElement::Alias(ScopedAlias {
                    scope_name: "WIDE1".to_string(),
                    max_count: 1,
                    remaining_count: 1,
                    completed: false,
                    serviced_by: None,
                }),
                PathElement::Strict(StrictTarget {
                    target_id: "dtn://igate/".to_string(),
                    completed: false,
                }),
            ],
            active_hop_index: 0,
            allow_substitution: Some(true),
        }),
        opportunistic_threshold: Some(0.65),
        spatial_scope: None,
        custom_attributes: Some(custom_attrs),
    };
    let encoded = mesh.encode_cbor().expect("encode mesh");
    let decoded = MeshRoutingData::decode_cbor(&encoded).expect("decode mesh");
    assert_eq!(decoded, mesh);

    // 2. Block 194 roundtrip
    let p194 = encode_spray_permit(12);
    assert_eq!(decode_spray_permit(&p194).expect("decode 194"), 12);

    // 3. TREB roundtrip
    let treb = TrebData {
        hops: vec![TrebHopEntry {
            node_eid: "dtn://node-a/".to_string(),
            arrival_time_ms: Some(1000),
            departure_time_ms: Some(1020),
            cla_info: Some("lora".to_string()),
        }],
    };
    let enc_treb = treb.encode_cbor().expect("encode treb");
    let dec_treb = TrebData::decode_cbor(&enc_treb).expect("decode treb");
    assert_eq!(dec_treb, treb);

    // 4. Arbitrary custom CBOR block (e.g., Block Type 222) inspected by a custom Rego rule
    let mut raw_custom = Vec::new();
    let val = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text("sar-emergency".to_string()),
        ),
        (
            ciborium::Value::Text("ttl_hint".to_string()),
            ciborium::Value::Integer(99.into()),
        ),
    ]);
    ciborium::into_writer(&val, &mut raw_custom).expect("cbor write");
    let json_val = decode_cbor_to_json(&raw_custom).expect("decode custom");
    assert_eq!(json_val["1"], "sar-emergency");
    assert_eq!(json_val["ttl_hint"], 99);

    let custom_ingress = r#"
package dtn.ingress
import rego.v1
import data.dtn.helpers

default decision := {
    "action": "DROP",
    "reason_code": 6,
    "reason": "Missing SAR tag",
    "generate_status_report": false,
    "route_key": null,
    "mutations": []
}

decision := {
    "action": "ACCEPT",
    "reason": "SAR emergency custom block verified",
    "generate_status_report": false,
    "route_key": null,
    "mutations": []
} if {
    blk := helpers.get_custom_block(input.bundle, 222)
    blk["1"] == "sar-emergency"
}
"#;
    let sources = PolicySources::default()
        .with_overrides(Some(custom_ingress), None)
        .expect("override");
    let custom_suite = PolicySuite::compile(sources).expect("compile custom");
    let custom_input = serde_json::json!({
        "bundle": base_bundle("dtn://src/1", "dtn://dest/1", vec![
            serde_json::json!({ "block_type": 222, "payload": json_val })
        ]),
        "node": base_node(),
        "current_dtn_time_ms": 2000,
    });
    let res = custom_suite.evaluate_ingress(&custom_input).expect("eval");
    assert_eq!(res.action, "ACCEPT");
}
