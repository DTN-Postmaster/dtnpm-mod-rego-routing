//! Unit/integration test simulating 3-node APRS forward-path routing
//! (`STATA -> STATB -> STATC`) driven exclusively by `RegoRoutingAgent` and
//! OPA/Rego policies (no static routes), modeled after Hardy's `spray_and_wait.rs`.

use core::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use dtnpm_core::mesh_blocks::{HopCountInfo, apply_routing_extensions, extract_routing_extensions};
use dtnpm_mod_rego_routing::{RegoRoutingConfig, RegoRoutingModule};
use dtnpm_web_core::module::WebModule;
use hardy_async::async_trait;
use hardy_async::sync::spin::Once;
use hardy_bpa::Bytes;
use hardy_bpa::bpa::{Bpa, BpaRegistration};
use hardy_bpa::cla::{
    Acceptance, Cla, ClaAddress, ClaInit, ForwardBundleResult, Result as ClaResult, Sink as ClaSink,
};
use hardy_bpa::services::{Service, ServiceSink, StatusNotify};
use hardy_bpa::stream::{Receiver, Segment, buffer_stream};
use hardy_bpv7::builder::Builder;
use hardy_bpv7::creation_timestamp::CreationTimestamp;
use hardy_bpv7::eid::{Eid, NodeId, Service as ServiceId};
use hardy_bpv7::parse::parse;
use hardy_bpv7::status_report::ReasonCode;
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

struct MockFileService {
    sink: Once<Box<dyn ServiceSink>>,
    delivered_tx: MpscSender<Bytes>,
}

#[async_trait]
impl Service for MockFileService {
    async fn on_register(&self, _source: &Eid, sink: Box<dyn ServiceSink>) {
        self.sink.call_once(|| sink);
    }

    async fn on_unregister(&self) {}

    async fn on_deliver(
        &self,
        _bundle_id: &hardy_bpv7::bundle::Id,
        _expiry: time::OffsetDateTime,
        total_len: u64,
        stream: &mut dyn Receiver<Segment>,
    ) -> hardy_bpa::services::Result<()> {
        let bundle = buffer_stream(stream, total_len).await?;
        let _ = self.delivered_tx.send(bundle).await;
        Ok(())
    }

    async fn on_status_notify(
        &self,
        _bundle_id: &hardy_bpv7::bundle::Id,
        _from: &Eid,
        _kind: StatusNotify,
        _reason: ReasonCode,
        _timestamp: Option<time::OffsetDateTime>,
    ) {
    }
}

async fn start_rego_node(callsign: &str, node_id_str: &str) -> Arc<Bpa> {
    let node_id: NodeId = node_id_str.parse().expect("valid node id");
    let cfg = RegoRoutingConfig {
        local_eid: node_id_str.to_string(),
        node_eids: vec![node_id_str.to_string()],
        callsign: Some(callsign.to_string()),
        record_treb: true,
        ..Default::default()
    };
    let module = RegoRoutingModule::with_config(cfg).expect("rego module");
    let mut builder = Bpa::builder()
        .node_ids([node_id].as_slice().try_into().expect("node ids"))
        .routing_agent("rego_routing".to_string(), module.routing_agent().clone());
    for pack in module.filter_packs() {
        builder = builder.add_filters(pack);
    }
    let bpa = Arc::new(builder.build().await.expect("bpa build"));
    bpa.start(false).await;
    bpa
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aprs_three_node_dynamic_via_routing_simulation() {
    let bpa_a = start_rego_node("STATA", "dtn://stata/").await;
    let bpa_b = start_rego_node("STATB", "dtn://statb/").await;
    let bpa_c = start_rego_node("STATC", "dtn://statc/").await;

    // 1. Register MockCla on STATA and inject bundle with APRS forward path "STATB",
    //    hop-limit 10, destination "dtn://statc/files" (no static routes anywhere!).
    let (cla_a_in, _) = MockCla::new();
    bpa_a
        .register_cla(
            "cla_a_in".to_string(),
            cla_a_in.clone(),
            None,
            ClaInit::default(),
        )
        .await
        .expect("cla_a_in");

    let src_eid: Eid = "dtn://stata/".parse().expect("src");
    let dst_eid: Eid = "dtn://statc/files".parse().expect("dst");
    let payload_text = b"Hello from STATA via STATB to STATC!";
    let builder = Builder::new(src_eid, dst_eid).with_payload(payload_text.as_slice().into());
    let builder = apply_routing_extensions(builder, Some(10), Some("STATB"), None)
        .expect("apply routing extensions");
    let (_bundle, raw_bundle) = builder
        .build(CreationTimestamp::now())
        .expect("build bundle");

    let mut wire_a = Bytes::from(raw_bundle.into_vec());
    let acceptance = cla_a_in
        .sink
        .get()
        .expect("cla_a_in sink")
        .dispatch(None, None, &mut wire_a)
        .await
        .expect("dispatch on STATA");
    assert_eq!(acceptance, Acceptance::Accepted);

    // 2. STATB connects to STATA over MockCla (simulating TCPCLv4).
    //    STATA's RegoRoutingAgent dynamically installed Via(dtn://statb/) from APRS path "STATB".
    let (cla_a_to_b, mut rx_at_b) = MockCla::new();
    bpa_a
        .register_cla(
            "cla_a_to_b".to_string(),
            cla_a_to_b.clone(),
            None,
            ClaInit::default(),
        )
        .await
        .expect("cla_a_to_b");
    let statb_node: NodeId = "dtn://statb/".parse().expect("statb node");
    cla_a_to_b
        .sink
        .get()
        .expect("cla_a_to_b sink")
        .add_peer(
            ClaAddress::Private(Bytes::from_static(b"statb")),
            &[statb_node],
        )
        .await
        .expect("add_peer statb on STATA");

    let wire_at_b = timeout(Duration::from_secs(5), rx_at_b.recv())
        .await
        .expect("timeout waiting for STATA -> STATB")
        .expect("rx_at_b closed");

    // 3. STATB ingests the bundle: Rego consumes "STATB" (MUTATE_APRS_STRICT) and
    //    STATB's RegoRoutingAgent dynamically adds Via(dtn://statc/).
    let (cla_b_in, _) = MockCla::new();
    bpa_b
        .register_cla(
            "cla_b_in".to_string(),
            cla_b_in.clone(),
            None,
            ClaInit::default(),
        )
        .await
        .expect("cla_b_in");
    let stata_node: NodeId = "dtn://stata/".parse().expect("stata node");
    let mut wire_b_in = wire_at_b;
    let acceptance_b = cla_b_in
        .sink
        .get()
        .expect("cla_b_in sink")
        .dispatch(Some(&stata_node), None, &mut wire_b_in)
        .await
        .expect("dispatch on STATB");
    assert_eq!(acceptance_b, Acceptance::Accepted);

    // 4. STATC connects to STATB over MockCla (simulating TCPCLv4).
    let (cla_b_to_c, mut rx_at_c) = MockCla::new();
    bpa_b
        .register_cla(
            "cla_b_to_c".to_string(),
            cla_b_to_c.clone(),
            None,
            ClaInit::default(),
        )
        .await
        .expect("cla_b_to_c");
    let statc_node: NodeId = "dtn://statc/".parse().expect("statc node");
    cla_b_to_c
        .sink
        .get()
        .expect("cla_b_to_c sink")
        .add_peer(
            ClaAddress::Private(Bytes::from_static(b"statc")),
            &[statc_node],
        )
        .await
        .expect("add_peer statc on STATB");

    let wire_at_c = timeout(Duration::from_secs(5), rx_at_c.recv())
        .await
        .expect("timeout waiting for STATB -> STATC")
        .expect("rx_at_c closed");

    // 5. STATC registers service "files" (dtn://statc/files) and ingests the bundle.
    let (delivered_tx, mut delivered_rx) = channel(4);
    let file_svc = Arc::new(MockFileService {
        sink: Once::new(),
        delivered_tx,
    });
    bpa_c
        .register_service(ServiceId::Dtn("files".into()), file_svc)
        .await
        .expect("register files service on STATC");

    let (cla_c_in, _) = MockCla::new();
    bpa_c
        .register_cla(
            "cla_c_in".to_string(),
            cla_c_in.clone(),
            None,
            ClaInit::default(),
        )
        .await
        .expect("cla_c_in");
    let statb_node_for_c: NodeId = "dtn://statb/".parse().expect("statb node");
    let mut wire_c_in = wire_at_c;
    let acceptance_c = cla_c_in
        .sink
        .get()
        .expect("cla_c_in sink")
        .dispatch(Some(&statb_node_for_c), None, &mut wire_c_in)
        .await
        .expect("dispatch on STATC");
    assert_eq!(acceptance_c, Acceptance::Accepted);

    let delivered_wire = timeout(Duration::from_secs(5), delivered_rx.recv())
        .await
        .expect("timeout waiting for delivery on STATC")
        .expect("delivered_rx closed");

    // 6. Inspect delivered bundle (just like `dtnprint` does).
    let parsed = parse(delivered_wire).expect("valid BPv7 bundle delivered at STATC");
    let payload = parsed
        .bundle
        .blocks
        .get(&1)
        .and_then(|b| b.payload(&parsed.data))
        .expect("payload block");
    assert_eq!(payload, payload_text);

    let ext = extract_routing_extensions(&parsed.bundle, &parsed.data);
    assert_eq!(
        ext.hop_count,
        Some(HopCountInfo {
            count: 2,
            limit: 10
        }),
        "STATA->STATB->STATC must increment hop_count to 2/10"
    );
    assert_eq!(
        ext.aprs_path_formatted.as_deref(),
        Some("STATB*"),
        "STATB must mark its APRS strict hop as completed"
    );
    let treb = ext.treb.expect("TREB trace block 201 must be present");
    let visited: Vec<&str> = treb.hops.iter().map(|h| h.node_eid.as_str()).collect();
    assert_eq!(visited, vec!["dtn://stata/", "dtn://statb/"]);
}
