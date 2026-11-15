//! End-to-end integration test verifying Spray-and-Wait opportunistic routing
//! with `RegoRoutingAgent` and `RouteAction::ForwardReplicate` on Hardy BPA.

use core::num::NonZeroU64;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use dtnpm_mod_rego_routing::blocks::{
    BLOCK_TYPE_SPRAY_PERMIT, DEFAULT_BLOCK_TYPE_TREB, TrebData, decode_spray_permit,
    encode_spray_permit,
};
use dtnpm_mod_rego_routing::{RegoRoutingConfig, RegoRoutingModule};
use dtnpm_web_core::WebModule;
use hardy_async::async_trait;
use hardy_async::sync::spin::Once;
use hardy_bpa::Bytes;
use hardy_bpa::bpa::{Bpa, BpaRegistration};
use hardy_bpa::cla::{
    Acceptance, Cla, ClaAddress, ClaInit, ForwardBundleResult, Result as ClaResult, Sink as ClaSink,
};
use hardy_bpa::stream::{Receiver, Segment, buffer_stream};
use hardy_bpv7::block::{Flags as BlockFlags, Type};
use hardy_bpv7::builder::Builder;
use hardy_bpv7::crc::CrcType;
use hardy_bpv7::creation_timestamp::CreationTimestamp;
use hardy_bpv7::eid::{Eid, IpnNodeId, NodeId};
use hardy_bpv7::parse::parse;
use hardy_eid_patterns::EidPattern;
use tokio::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel};
use tokio::time::timeout;

struct MockCla {
    sink: Once<Box<dyn ClaSink>>,
    forwarded_tx: MpscSender<Bytes>,
}

impl MockCla {
    fn new() -> (Arc<Self>, MpscReceiver<Bytes>) {
        let (tx, rx) = channel(16);
        (
            Arc::new(Self {
                sink: Once::new(),
                forwarded_tx: tx,
            }),
            rx,
        )
    }
}

#[async_trait]
impl Cla for MockCla {
    async fn on_register(
        &self,
        sink: Box<dyn ClaSink>,
        _node_ids: &[NodeId],
        _max_bundle_size: Option<NonZeroU64>,
    ) {
        self.sink.call_once(|| sink);
    }

    async fn on_unregister(&self) {}

    async fn forward(
        &self,
        _lane: Option<u32>,
        _cla_addr: &ClaAddress,
        _bundle_id: &hardy_bpv7::bundle::Id,
        total_len: u64,
        stream: &mut dyn Receiver<Segment>,
    ) -> ClaResult<ForwardBundleResult> {
        let bundle = buffer_stream(stream, total_len).await?;
        let _ = self.forwarded_tx.send(bundle).await;
        Ok(ForwardBundleResult::Sent)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spray_and_wait_forward_replicate_retains_and_splits_permits() {
    let local_node = NodeId::Ipn(IpnNodeId {
        allocator_id: 0,
        node_number: 1,
    });
    let cfg = RegoRoutingConfig {
        local_eid: "ipn:0.1.0".to_string(),
        node_eids: vec!["ipn:0.1.0".to_string()],
        record_treb: true,
        treb_block_type: DEFAULT_BLOCK_TYPE_TREB,
        ..Default::default()
    };
    let module = RegoRoutingModule::with_config(cfg).expect("init rego module");
    let agent = module.routing_agent().clone();

    let mut builder = Bpa::builder()
        .node_ids([local_node].as_slice().try_into().expect("node ids"))
        .routing_agent("rego_routing".to_string(), agent.clone());
    for pack in module.filter_packs() {
        builder = builder.add_filters(pack);
    }
    let bpa = Arc::new(builder.build().await.expect("bpa build"));
    bpa.start(false).await;

    // 1. Ingest Spray-and-Wait bundle with initial L = 4 toward ipn:0.99.1
    let (cla_in, _) = MockCla::new();
    bpa.register_cla(
        "cla_in".to_string(),
        cla_in.clone(),
        None,
        ClaInit::default(),
    )
    .await
    .expect("register cla_in");

    let src_eid: Eid = "ipn:0.1.1".parse().expect("src");
    let dst_eid: Eid = "ipn:0.99.1".parse().expect("dst");
    let mut bldr = Builder::new(src_eid, dst_eid)
        .with_payload(Cow::Borrowed(b"Spray-and-Wait ForwardReplicate payload"));
    bldr = bldr
        .add_extension_block(Type::Unrecognised(BLOCK_TYPE_SPRAY_PERMIT))
        .expect("add spray block")
        .with_flags(BlockFlags {
            must_replicate: true,
            ..Default::default()
        })
        .with_crc_type(CrcType::None)
        .build(Cow::Owned(encode_spray_permit(4).into_vec()));

    let (bundle, raw_bundle) = bldr.build(CreationTimestamp::now()).expect("build bundle");
    let mut wire = Bytes::from(raw_bundle);
    let acceptance = cla_in
        .sink
        .get()
        .expect("cla_in sink")
        .dispatch(None, None, &mut wire)
        .await
        .expect("dispatch");
    assert_eq!(acceptance, Acceptance::Accepted);
    assert_eq!(module.engine().tracked_spray_quota(&bundle), Some(4));

    let target_pattern: EidPattern = "ipn:0.99.*".parse().expect("pattern");

    // 2. Relay 1 (node 2) connects: ForwardReplicate splits 4 -> tx=2, local=2 (retained!)
    let (cla_r1, mut rx_r1) = MockCla::new();
    bpa.register_cla(
        "cla_r1".to_string(),
        cla_r1.clone(),
        None,
        ClaInit::default(),
    )
    .await
    .expect("register cla_r1");
    let r1_node = NodeId::Ipn(IpnNodeId {
        allocator_id: 0,
        node_number: 2,
    });
    let r1_eid: Eid = "ipn:0.2.0".parse().expect("r1 eid");
    cla_r1
        .sink
        .get()
        .expect("cla_r1 sink")
        .add_peer(ClaAddress::Private(Bytes::from_static(b"r1")), &[r1_node])
        .await
        .expect("add_peer r1");

    let added_r1 = agent
        .add_spray_route_for_bundle(target_pattern.clone(), r1_eid.clone(), &bundle, None)
        .await
        .expect("add_spray_route r1");
    assert!(added_r1, "Relay 1 must be added while L=4 > 1");

    let copy_r1 = timeout(Duration::from_secs(5), rx_r1.recv())
        .await
        .expect("timeout r1")
        .expect("rx_r1 closed");
    let parsed_r1 = parse(copy_r1).expect("parse r1");
    let quota_r1 = parsed_r1
        .bundle
        .blocks
        .values()
        .find(|b| u64::from(b.block_type) == BLOCK_TYPE_SPRAY_PERMIT)
        .and_then(|b| b.payload(&parsed_r1.data))
        .and_then(|p| decode_spray_permit(p).ok());
    assert_eq!(quota_r1, Some(2), "Relay 1 must receive floor(4/2) = 2");
    assert_eq!(module.engine().tracked_spray_quota(&bundle), Some(2));

    agent
        .remove_spray_route(&target_pattern, r1_eid, None)
        .await
        .expect("remove_spray_route r1");

    // 3. Relay 2 (node 3) connects: ForwardReplicate splits 2 -> tx=1, local=1 (retained!)
    let (cla_r2, mut rx_r2) = MockCla::new();
    bpa.register_cla(
        "cla_r2".to_string(),
        cla_r2.clone(),
        None,
        ClaInit::default(),
    )
    .await
    .expect("register cla_r2");
    let r2_node = NodeId::Ipn(IpnNodeId {
        allocator_id: 0,
        node_number: 3,
    });
    let r2_eid: Eid = "ipn:0.3.0".parse().expect("r2 eid");
    cla_r2
        .sink
        .get()
        .expect("cla_r2 sink")
        .add_peer(ClaAddress::Private(Bytes::from_static(b"r2")), &[r2_node])
        .await
        .expect("add_peer r2");

    let added_r2 = agent
        .add_spray_route_for_bundle(target_pattern.clone(), r2_eid.clone(), &bundle, None)
        .await
        .expect("add_spray_route r2");
    assert!(added_r2, "Relay 2 must be added while L=2 > 1");

    let copy_r2 = timeout(Duration::from_secs(5), rx_r2.recv())
        .await
        .expect("timeout r2")
        .expect("rx_r2 closed");
    let parsed_r2 = parse(copy_r2).expect("parse r2");
    let quota_r2 = parsed_r2
        .bundle
        .blocks
        .values()
        .find(|b| u64::from(b.block_type) == BLOCK_TYPE_SPRAY_PERMIT)
        .and_then(|b| b.payload(&parsed_r2.data))
        .and_then(|p| decode_spray_permit(p).ok());
    assert_eq!(quota_r2, Some(1), "Relay 2 must receive floor(2/2) = 1");
    assert_eq!(module.engine().tracked_spray_quota(&bundle), Some(1));

    agent
        .remove_spray_route(&target_pattern, r2_eid, None)
        .await
        .expect("remove_spray_route r2");

    // 4. Relay 3 (node 4) connects in WAIT phase (L=1): add_spray_route_for_bundle must refuse
    let r3_eid: Eid = "ipn:0.4.0".parse().expect("r3 eid");
    let added_r3 = agent
        .add_spray_route_for_bundle(target_pattern, r3_eid, &bundle, None)
        .await
        .expect("add_spray_route r3");
    assert!(
        !added_r3,
        "Relay 3 route must not be added once Wait phase (L = 1) is reached"
    );

    // 5. Destination (node 99) connects: retained bundle is delivered directly with TREB recorded
    let (cla_dst, mut rx_dst) = MockCla::new();
    bpa.register_cla(
        "cla_dst".to_string(),
        cla_dst.clone(),
        None,
        ClaInit::default(),
    )
    .await
    .expect("register cla_dst");
    let dst_node = NodeId::Ipn(IpnNodeId {
        allocator_id: 0,
        node_number: 99,
    });
    cla_dst
        .sink
        .get()
        .expect("cla_dst sink")
        .add_peer(ClaAddress::Private(Bytes::from_static(b"dst")), &[dst_node])
        .await
        .expect("add_peer dst");

    let delivered = timeout(Duration::from_secs(5), rx_dst.recv())
        .await
        .expect("timeout dst")
        .expect("rx_dst closed");
    let parsed_dst = parse(delivered).expect("parse dst");
    assert_eq!(
        parsed_dst.bundle.primary.destination.to_string(),
        "ipn:99.1"
    );
    let treb = parsed_dst
        .bundle
        .blocks
        .values()
        .find(|b| u64::from(b.block_type) == DEFAULT_BLOCK_TYPE_TREB)
        .and_then(|b| b.payload(&parsed_dst.data))
        .and_then(|p| TrebData::decode_cbor(p).ok())
        .expect("TREB block must be recorded on direct delivery");
    assert_eq!(treb.hops.len(), 1);
    assert_eq!(treb.hops[0].node_eid, "ipn:1.0");

    bpa.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rego_routing_agent_installs_forward_replicate_on_observed_peer() {
    let local_node = NodeId::Ipn(IpnNodeId {
        allocator_id: 0,
        node_number: 1,
    });
    let custom_routing = r#"
package dtn.routing

import data.dtn.helpers

routes contains {
    "pattern": "ipn:0.99.*",
    "action": "FORWARD_REPLICATE",
    "next_hop": peer.peer_eid,
    "priority": 100,
    "reason_code": 1,
} if {
    some peer in input.peers
    helpers.peer_allowed(peer, input.node)
}
"#;

    let module = Arc::new(
        RegoRoutingModule::with_config(RegoRoutingConfig {
            local_eid: "ipn:0.1.0".to_string(),
            node_eids: vec!["ipn:0.1.0".to_string()],
            custom_routing_rego: Some(custom_routing.to_string()),
            ..Default::default()
        })
        .expect("module"),
    );

    let mut builder = Bpa::builder()
        .status_reports(false)
        .node_ids([local_node].as_slice().try_into().expect("node ids"));

    for pack in module.filter_packs() {
        builder = builder.add_filters(pack);
    }
    builder = builder.routing_agent("rego_routing".to_string(), module.routing_agent().clone());

    let bpa = Arc::new(builder.build().await.expect("build bpa"));
    bpa.start(false).await;

    let (cla_in, _rx_in) = MockCla::new();
    bpa.register_cla(
        "cla_in".to_string(),
        cla_in.clone(),
        None,
        ClaInit::default(),
    )
    .await
    .expect("register cla_in");

    let (cla_r1, mut rx_r1) = MockCla::new();
    let observed_r1: Arc<dyn hardy_bpa::cla::Cla> = dtnpm_core::cla_observer::ObservedCla::wrap(
        "cla_r1",
        "mock",
        cla_r1.clone(),
        module.engine().clone(),
    );
    bpa.register_cla("cla_r1".to_string(), observed_r1, None, ClaInit::default())
        .await
        .expect("register observed cla_r1");

    let mut bldr = Builder::new(
        "ipn:0.1.1".parse().expect("src"),
        "ipn:0.99.1".parse().expect("dst"),
    )
    .with_payload(Cow::Borrowed(b"snw-rego-agent"));
    bldr = bldr
        .add_extension_block(Type::Unrecognised(BLOCK_TYPE_SPRAY_PERMIT))
        .expect("add spray block")
        .with_flags(BlockFlags {
            must_replicate: true,
            ..Default::default()
        })
        .with_crc_type(CrcType::None)
        .build(Cow::Owned(encode_spray_permit(4).into_vec()));

    let (bundle, raw_bundle) = bldr.build(CreationTimestamp::now()).expect("build bundle");
    let mut wire = Bytes::from(raw_bundle);
    let acceptance = cla_in
        .sink
        .get()
        .expect("cla_in sink")
        .dispatch(None, None, &mut wire)
        .await
        .expect("dispatch");
    assert_eq!(acceptance, Acceptance::Accepted);

    let r1_node = NodeId::Ipn(IpnNodeId {
        allocator_id: 0,
        node_number: 2,
    });
    cla_r1
        .sink
        .get()
        .expect("cla_r1 sink")
        .add_peer(
            ClaAddress::Private(Bytes::from_static(b"r1")),
            &[r1_node.clone()],
        )
        .await
        .expect("add_peer r1");

    let copy_r1 = timeout(Duration::from_secs(5), rx_r1.recv())
        .await
        .expect("timeout waiting for RegoRoutingAgent to install ForwardReplicate route")
        .expect("rx_r1 closed");
    let parsed_r1 = parse(copy_r1).expect("parse r1");
    let quota_r1 = parsed_r1
        .bundle
        .blocks
        .values()
        .find(|b| u64::from(b.block_type) == BLOCK_TYPE_SPRAY_PERMIT)
        .and_then(|b| b.payload(&parsed_r1.data))
        .and_then(|p| decode_spray_permit(p).ok());
    assert_eq!(quota_r1, Some(2), "Relay 1 must receive floor(4/2) = 2");
    assert_eq!(module.engine().tracked_spray_quota(&bundle), Some(2));

    cla_r1
        .sink
        .get()
        .expect("cla_r1 sink")
        .remove_peer(&ClaAddress::Private(Bytes::from_static(b"r1")))
        .await
        .expect("remove_peer r1");

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(module.engine().peers_snapshot().is_empty());

    bpa.shutdown().await;
}
