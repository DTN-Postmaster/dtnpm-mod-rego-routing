//! End-to-end integration tests with a real Hardy BPA pipeline (`Bpa::builder().add_filters(...)`)
//! verifying Rego ingress blacklist drops, RFC 9171 §4.3.3 Hop Count drops, and extension block
//! forwarding/rewriting (TREB Type 201 & Spray-and-Wait Type 194).

use core::num::{NonZeroU8, NonZeroU64};
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use dtnpm_mod_rego_routing::blocks::{
    BLOCK_TYPE_SPRAY_PERMIT, DEFAULT_BLOCK_TYPE_TREB, TrebData, decode_spray_permit,
    encode_spray_permit,
};
use dtnpm_mod_rego_routing::{BlacklistEntry, RegoRoutingConfig, RegoRoutingModule};
use dtnpm_web_core::WebModule;
use hardy_async::sync::spin::Once;
use hardy_bpa::{
    Bytes, async_trait,
    bpa::{Bpa, BpaRegistration},
    cla::{self, Cla, ClaAddress, ClaInit, ForwardBundleResult, Sink},
    node_ids::NodeIds,
    routing::{RouteAction, StaticRoutingAgent},
    stream::{Receiver, Segment, buffer_stream},
};
use hardy_bpv7::{
    block::{Flags as BlockFlags, Type},
    builder::Builder,
    crc::CrcType,
    creation_timestamp::CreationTimestamp,
    eid::{Eid, IpnNodeId, NodeId},
    hop_info::HopInfo,
    parse::parse,
};
use hardy_eid_patterns::EidPattern;

struct CapturingCla {
    sink: Once<Box<dyn Sink>>,
    forwarded_tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
}

impl CapturingCla {
    fn new(forwarded_tx: tokio::sync::mpsc::UnboundedSender<Bytes>) -> Self {
        Self {
            sink: Once::new(),
            forwarded_tx,
        }
    }

    fn sink(&self) -> &dyn Sink {
        self.sink.get().expect("CLA must be registered").as_ref()
    }
}

#[async_trait]
impl Cla for CapturingCla {
    async fn on_register(
        &self,
        sink: Box<dyn Sink>,
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
    ) -> cla::Result<ForwardBundleResult> {
        let bundle = buffer_stream(stream, total_len).await?;
        let _ = self.forwarded_tx.send(bundle);
        Ok(ForwardBundleResult::Sent)
    }
}

#[tokio::test]
async fn hardy_bpa_pipeline_enforces_blacklist_hop_limit_and_rewrites() {
    let config = RegoRoutingConfig {
        local_eid: "ipn:1.0".to_string(),
        node_eids: vec!["ipn:1.0".to_string()],
        record_treb: true,
        treb_block_type: DEFAULT_BLOCK_TYPE_TREB,
        ..Default::default()
    };
    let module = RegoRoutingModule::with_config(config).expect("init rego module");
    module.engine().upsert_blacklist_entry(BlacklistEntry {
        id: "bl-test".to_string(),
        eid_pattern: "ipn:99.*".to_string(),
        reason: "Blocked spammer".to_string(),
        enabled: true,
        created_at: 0,
        created_by: "test".to_string(),
    });

    let node_id = NodeId::Ipn(IpnNodeId {
        allocator_id: 0,
        node_number: 1,
    });
    let peer_node = NodeId::Ipn(IpnNodeId {
        allocator_id: 0,
        node_number: 2,
    });
    let peer_eid: Eid = "ipn:2.0".parse().expect("peer eid");
    let dest_pattern: EidPattern = "ipn:5.*".parse().expect("dest pattern");
    let static_agent = Arc::new(StaticRoutingAgent::new(&[(
        dest_pattern,
        RouteAction::Via(peer_eid),
        10,
    )]));

    let mut builder =
        Bpa::builder().node_ids(NodeIds::try_from([node_id].as_slice()).expect("node ids"));
    for pack in module.filter_packs() {
        builder = builder.add_filters(pack);
    }
    builder = builder.routing_agent("static".to_string(), static_agent);
    let bpa = builder.build().await.expect("build bpa");
    bpa.start(false).await;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let cla = Arc::new(CapturingCla::new(tx));
    bpa.register_cla("cap".to_string(), cla.clone(), None, ClaInit::default())
        .await
        .expect("register cla");

    let peer_addr = ClaAddress::Private("peer-2".as_bytes().into());
    cla.sink()
        .add_peer(peer_addr, &[peer_node])
        .await
        .expect("add peer");

    // 1. Blacklisted source bundle (ipn:99.1 -> ipn:5.1) MUST be dropped at ingress
    let (_, bad_bytes) = Builder::new("ipn:99.1".parse().unwrap(), "ipn:5.1".parse().unwrap())
        .with_payload(Cow::Borrowed(b"spam"))
        .build(CreationTimestamp::now())
        .expect("build spam");
    let mut bad_stream = Bytes::from(bad_bytes);
    let _ = cla.sink().dispatch(None, None, &mut bad_stream).await;

    // 2. Exceeded Hop Count bundle (count=4, limit=5) MUST be dropped at ingress (4+1 >= 5)
    let (_, hop_exceeded) = Builder::new("ipn:3.1".parse().unwrap(), "ipn:5.1".parse().unwrap())
        .with_hop_count(&HopInfo {
            limit: NonZeroU8::new(5).unwrap(),
            count: 4,
        })
        .with_payload(Cow::Borrowed(b"too-many-hops"))
        .build(CreationTimestamp::now())
        .expect("build hop exceeded");
    let mut hop_stream = Bytes::from(hop_exceeded);
    let _ = cla.sink().dispatch(None, None, &mut hop_stream).await;

    // 3. Valid Spray-and-Wait (Block 194 quota=6) + Hop Count (1/5) MUST be forwarded
    //    with transmitted quota split to 3 and TREB Block 201 appended!
    let mut valid_builder = Builder::new("ipn:3.2".parse().unwrap(), "ipn:5.2".parse().unwrap())
        .with_hop_count(&HopInfo {
            limit: NonZeroU8::new(5).unwrap(),
            count: 1,
        })
        .with_payload(Cow::Borrowed(b"hello-dtn"));
    valid_builder = valid_builder
        .add_extension_block(Type::Unrecognised(BLOCK_TYPE_SPRAY_PERMIT))
        .expect("add spray block")
        .with_flags(BlockFlags {
            must_replicate: true,
            ..Default::default()
        })
        .with_crc_type(CrcType::None)
        .build(Cow::Owned(encode_spray_permit(6).into_vec()));

    let (_, valid_bytes) = valid_builder
        .build(CreationTimestamp::now())
        .expect("build valid");
    let mut valid_stream = Bytes::from(valid_bytes);
    let _ = cla
        .sink()
        .dispatch(None, None, &mut valid_stream)
        .await
        .expect("dispatch valid");

    let forwarded = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for forwarded bundle")
        .expect("forwarded channel closed");

    // Ensure no unexpected spam/hop-exceeded bundle arrived before or after
    let extra = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
    assert!(extra.is_err(), "only the valid bundle should be forwarded");

    let parsed = parse(forwarded).expect("parse forwarded bundle");
    assert_eq!(parsed.bundle.primary.id.source.to_string(), "ipn:3.2");

    // Verify Block 194 quota was split to floor(6/2) = 3 on wire
    let mut found_194 = None;
    let mut found_treb = None;
    for blk in parsed.bundle.blocks.values() {
        let bt = u64::from(blk.block_type);
        if bt == BLOCK_TYPE_SPRAY_PERMIT {
            let payload = blk.payload(&parsed.data).expect("payload 194");
            found_194 = Some(decode_spray_permit(payload).expect("decode 194"));
        } else if bt == DEFAULT_BLOCK_TYPE_TREB {
            let payload = blk.payload(&parsed.data).expect("payload treb");
            found_treb = Some(TrebData::decode_cbor(payload).expect("decode treb"));
        }
    }

    assert_eq!(found_194, Some(3), "binary spray must split 6 -> 3 on wire");
    let treb = found_treb.expect("TREB block 201 must be inserted");
    assert_eq!(treb.hops.len(), 1);
    assert_eq!(treb.hops[0].node_eid, "ipn:1.0");
    assert!(treb.hops[0].arrival_time_ms.is_some());
    assert!(treb.hops[0].departure_time_ms.is_some());

    bpa.shutdown().await;
}
