//! Integration test for [`RegoRib`] per-bundle `data.dtn.routing.decide`
//! routing via `Bpa::builder().rib(...)`.

use core::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use dtnpm_mod_rego_routing::{
    PolicySources, PolicySuite, RegoRib, RegoRoutingConfig, RegoRoutingModule, build_filter_pack,
};
use hardy_async::async_trait;
use hardy_async::sync::spin::Once;
use hardy_bpa::Bytes;
use hardy_bpa::bpa::Bpa;
use hardy_bpa::cla::{
    Acceptance, Cla, ClaAddress, ClaInit, ForwardBundleResult, Result as ClaResult, Sink as ClaSink,
};
use hardy_bpa::services::{Result as ServiceResult, Service, ServiceSink, StatusNotify};
use hardy_bpa::stream::{Receiver, Segment, buffer_stream};
use hardy_bpv7::builder::Builder;
use hardy_bpv7::eid::{Eid, NodeId, Service as ServiceId};
use hardy_bpv7::parse::parse;
use hardy_bpv7::status_report::ReasonCode;
use tokio::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel};
use tokio::time::timeout;

struct MockCla {
    sink: Once<Box<dyn ClaSink>>,
    forwarded_tx: MpscSender<(String, Eid)>,
}

impl MockCla {
    fn new() -> (Arc<Self>, MpscReceiver<(String, Eid)>) {
        let (tx, rx) = channel(16);
        (
            Arc::new(Self {
                sink: Once::new(),
                forwarded_tx: tx,
            }),
            rx,
        )
    }

    async fn connect_peer(&self, node_id: NodeId) {
        let sink = self.sink.get().expect("CLA not registered");
        sink.add_peer(
            ClaAddress::Private(Bytes::from(node_id.to_string())),
            &[node_id],
        )
        .await
        .expect("add_peer failed");
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
        cla_addr: &ClaAddress,
        _bundle_id: &hardy_bpv7::bundle::Id,
        total_len: u64,
        stream: &mut dyn Receiver<Segment>,
    ) -> ClaResult<ForwardBundleResult> {
        let data = buffer_stream(stream, total_len).await?;
        let parsed = parse(data).expect("parse forwarded bundle");
        let addr_str = match cla_addr {
            ClaAddress::Private(b) => String::from_utf8_lossy(b).into_owned(),
            other => format!("{other:?}"),
        };
        let _ = self
            .forwarded_tx
            .send((addr_str, parsed.bundle.primary.destination))
            .await;
        Ok(ForwardBundleResult::Sent)
    }
}

struct MockService {
    delivered_tx: MpscSender<Eid>,
}

#[async_trait]
impl Service for MockService {
    async fn on_register(&self, _source: &Eid, _sink: Box<dyn ServiceSink>) {}
    async fn on_unregister(&self) {}
    async fn on_status_notify(
        &self,
        _bundle_id: &hardy_bpv7::bundle::Id,
        _from: &Eid,
        _kind: StatusNotify,
        _reason: ReasonCode,
        _timestamp: Option<time::OffsetDateTime>,
    ) {
    }
    async fn on_deliver(
        &self,
        bundle_id: &hardy_bpv7::bundle::Id,
        _expiry: time::OffsetDateTime,
        _total_len: u64,
        _stream: &mut dyn Receiver<Segment>,
    ) -> ServiceResult<()> {
        let _ = self.delivered_tx.send(bundle_id.source.clone()).await;
        Ok(())
    }
}

fn build_bundle(src: &Eid, dst: &Eid, payload: &[u8]) -> Bytes {
    Builder::new(src.clone(), dst.clone())
        .with_payload(std::borrow::Cow::Borrowed(payload))
        .build(hardy_bpv7::creation_timestamp::CreationTimestamp::now())
        .expect("build bundle")
        .1
        .into()
}

#[tokio::test]
async fn rego_rib_per_bundle_size_wait_drop_and_local_delivery() {
    let custom_routing = r#"
package dtn.routing

import rego.v1

default routes := []

decide := {"action": "WAIT"} if {
    startswith(input.bundle.destination, "dtn://deferred/")
} else := {"action": "DROP", "reason_code": 6} if {
    startswith(input.bundle.destination, "dtn://dropped/")
} else := {"action": "FORWARD", "next_hop": "dtn://laterpeer/", "retain": false} if {
    startswith(input.bundle.destination, "dtn://later/")
} else := {"action": "FORWARD", "next_hop": "dtn://bigpeer/", "retain": false} if {
    input.bundle.payload_len >= 100
} else := {"action": "FORWARD", "next_hop": "dtn://smallpeer/", "retain": false} if {
    input.bundle.payload_len < 100
}
"#;

    let local_node: NodeId = "dtn://local/".parse().expect("local node");
    let big_peer: NodeId = "dtn://bigpeer/".parse().expect("big peer");
    let small_peer: NodeId = "dtn://smallpeer/".parse().expect("small peer");
    let later_peer: NodeId = "dtn://laterpeer/".parse().expect("later peer");

    let cfg = RegoRoutingConfig {
        local_eid: "dtn://local/".to_string(),
        node_eids: vec!["dtn://local/".to_string()],
        custom_routing_rego: Some(custom_routing.to_string()),
        ..Default::default()
    };
    let module = Arc::new(RegoRoutingModule::with_config(cfg).expect("module"));

    let (cla, mut forwarded_rx) = MockCla::new();
    let (delivered_tx, mut delivered_rx) = channel(16);
    let service = Arc::new(MockService { delivered_tx });

    let engine = module.engine().clone();
    let bpa = Bpa::builder()
        .node_ids([local_node].as_slice().try_into().unwrap())
        .poll_channel_depth(NonZeroU64::new(16).unwrap().try_into().unwrap())
        .add_filters(build_filter_pack(module.engine().clone()))
        .cla("mock", cla.clone(), None, ClaInit::default())
        .service(service, ServiceId::Dtn("svc".into()))
        .routing_agent("rego_routing".to_string(), module.routing_agent().clone())
        .rib(move |default_rib| Arc::new(RegoRib::new(default_rib, engine)))
        .build()
        .await
        .expect("build BPA");

    bpa.start(false).await;
    cla.connect_peer(big_peer).await;
    cla.connect_peer(small_peer).await;

    let sink = cla.sink.get().expect("CLA sink");
    let src_node: NodeId = "dtn://src/".parse().expect("src node");
    let src_eid: Eid = "dtn://src/app".parse().expect("src eid");

    // 1. Deferred bundle -> WAIT (parked until policy updates)
    let deferred_dst: Eid = "dtn://deferred/inbox".parse().unwrap();
    let mut deferred = build_bundle(&src_eid, &deferred_dst, b"hold");
    assert_eq!(
        sink.dispatch(Some(&src_node), None, &mut deferred)
            .await
            .unwrap(),
        Acceptance::Accepted
    );

    // 2. Dropped bundle -> DROP (deleted immediately; must NOT wake up on later policy change)
    let dropped_dst: Eid = "dtn://dropped/inbox".parse().unwrap();
    let mut dropped = build_bundle(&src_eid, &dropped_dst, b"drop");
    assert_eq!(
        sink.dispatch(Some(&src_node), None, &mut dropped)
            .await
            .unwrap(),
        Acceptance::Accepted
    );

    // 3. Target peer not yet connected -> WAIT until later_peer connects
    let later_dst: Eid = "dtn://later/inbox".parse().unwrap();
    let mut later = build_bundle(&src_eid, &later_dst, b"later");
    assert_eq!(
        sink.dispatch(Some(&src_node), None, &mut later)
            .await
            .unwrap(),
        Acceptance::Accepted
    );

    // 4. Local service bundle -> local Deliver preserved despite RegoRib decide rules
    let mut local = build_bundle(&src_eid, &"dtn://local/svc".parse().unwrap(), b"local");
    assert_eq!(
        sink.dispatch(Some(&src_node), None, &mut local)
            .await
            .unwrap(),
        Acceptance::Accepted
    );

    // 5. Exact payload_len boundary: 99 bytes (< 100) -> forwarded to dtn://smallpeer/
    let small_dst: Eid = "dtn://remote/small".parse().unwrap();
    let mut small = build_bundle(&src_eid, &small_dst, &[b's'; 99]);
    assert_eq!(
        sink.dispatch(Some(&src_node), None, &mut small)
            .await
            .unwrap(),
        Acceptance::Accepted
    );

    // 6. Exact payload_len boundary: 100 bytes (>= 100) -> forwarded to dtn://bigpeer/
    let big_dst: Eid = "dtn://remote/big".parse().unwrap();
    let mut big = build_bundle(&src_eid, &big_dst, &[b'X'; 100]);
    assert_eq!(
        sink.dispatch(Some(&src_node), None, &mut big)
            .await
            .unwrap(),
        Acceptance::Accepted
    );

    let deliv = timeout(Duration::from_secs(3), delivered_rx.recv())
        .await
        .expect("local delivery timeout")
        .expect("delivered channel");
    assert_eq!(deliv, src_eid);

    let mut fwd = Vec::new();
    for _ in 0..2 {
        let item = timeout(Duration::from_secs(3), forwarded_rx.recv())
            .await
            .expect("forward timeout")
            .expect("forwarded channel");
        fwd.push(item);
    }

    assert!(
        fwd.contains(&("dtn://smallpeer/".to_string(), small_dst)),
        "expected 99-byte bundle on smallpeer, got {fwd:?}"
    );
    assert!(
        fwd.contains(&("dtn://bigpeer/".to_string(), big_dst)),
        "expected 100-byte bundle on bigpeer, got {fwd:?}"
    );

    // Connect later_peer -> parked bundle for dtn://later/inbox must wake up and forward!
    cla.connect_peer(later_peer).await;
    let later_fwd = timeout(Duration::from_secs(3), forwarded_rx.recv())
        .await
        .expect("later_peer wakeup timeout")
        .expect("forwarded channel");
    assert_eq!(later_fwd, ("dtn://laterpeer/".to_string(), later_dst));

    // Update routing policy so deferred (and even dropped, if it were still alive) would forward.
    // Only `deferred` should wake up and forward; `dropped` was already deleted.
    let relaxed_routing = r#"
package dtn.routing

import rego.v1

default routes := []

decide := {"action": "FORWARD", "next_hop": "dtn://smallpeer/", "retain": false} if {
    startswith(input.bundle.destination, "dtn://deferred/")
} else := {"action": "FORWARD", "next_hop": "dtn://smallpeer/", "retain": false} if {
    startswith(input.bundle.destination, "dtn://dropped/")
}
"#;
    module
        .engine()
        .update_policy_with_routing(
            "custom".to_string(),
            32,
            200,
            None,
            None,
            Some(relaxed_routing.to_string()),
        )
        .expect("update_policy_with_routing");

    let deferred_fwd = timeout(Duration::from_secs(3), forwarded_rx.recv())
        .await
        .expect("deferred policy-update wakeup timeout")
        .expect("forwarded channel");
    assert_eq!(deferred_fwd, ("dtn://smallpeer/".to_string(), deferred_dst));

    // Dropped bundle must never appear even after policy relaxation.
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        forwarded_rx.try_recv().is_err(),
        "dropped bundle unexpectedly forwarded"
    );

    bpa.shutdown().await;
}

#[test]
fn policy_suite_rejects_broken_decide_rule_instead_of_silently_ignoring() {
    let broken_routing = r#"
package dtn.routing

import rego.v1

default routes := []

decide := {"action": "FORWARD"} if {
    x == 1
}
"#;
    let sources = PolicySources::default()
        .with_all_overrides(None, None, Some(broken_routing))
        .expect("sources");
    assert!(
        PolicySuite::compile(sources).is_err(),
        "broken decide rule must fail compilation"
    );
}

#[tokio::test]
async fn rego_rib_fallback_and_peer_id_selection() {
    let routing = r#"
package dtn.routing

import rego.v1

default routes := []

routes contains {
    "pattern": "dtn://fallback/**",
    "action": "VIA",
    "next_hop": "dtn://peer_a/",
    "priority": 90,
}

decide := {"action": "FALLBACK"} if {
    startswith(input.bundle.destination, "dtn://fallback/")
} else := {
    "action": "FORWARD_REPLICATE",
    "next_hop": "dtn://peer_b/",
    "peer_id": peer.peer_id,
    "retain": true,
} if {
    startswith(input.bundle.destination, "dtn://replicate/")
    some peer in input.peers
    peer.peer_eid == "dtn://peer_b/"
}
"#;

    let local_node: NodeId = "dtn://local/".parse().expect("local node");
    let peer_a: NodeId = "dtn://peer_a/".parse().expect("peer_a");
    let peer_b: NodeId = "dtn://peer_b/".parse().expect("peer_b");

    let cfg = RegoRoutingConfig {
        local_eid: "dtn://local/".to_string(),
        node_eids: vec!["dtn://local/".to_string()],
        custom_routing_rego: Some(routing.to_string()),
        ..Default::default()
    };
    let module = Arc::new(RegoRoutingModule::with_config(cfg).expect("module"));
    let (cla, mut forwarded_rx) = MockCla::new();
    let (delivered_tx, _delivered_rx) = channel(4);
    let service = Arc::new(MockService { delivered_tx });

    let engine = module.engine().clone();
    let bpa = Bpa::builder()
        .node_ids([local_node].as_slice().try_into().unwrap())
        .poll_channel_depth(NonZeroU64::new(16).unwrap().try_into().unwrap())
        .add_filters(build_filter_pack(module.engine().clone()))
        .cla("mock", cla.clone(), None, ClaInit::default())
        .service(service, ServiceId::Dtn("svc".into()))
        .routing_agent("rego_routing".to_string(), module.routing_agent().clone())
        .rib(move |default_rib| Arc::new(RegoRib::new(default_rib, engine)))
        .build()
        .await
        .expect("build BPA");

    bpa.start(false).await;
    cla.connect_peer(peer_a).await;
    cla.connect_peer(peer_b).await;

    let sink = cla.sink.get().expect("CLA sink");
    let src_node: NodeId = "dtn://src/".parse().expect("src node");
    let src_eid: Eid = "dtn://src/app".parse().expect("src eid");

    let fb_dst: Eid = "dtn://fallback/inbox".parse().unwrap();
    let mut fb_bundle = build_bundle(&src_eid, &fb_dst, b"fb");
    assert_eq!(
        sink.dispatch(Some(&src_node), None, &mut fb_bundle)
            .await
            .unwrap(),
        Acceptance::Accepted
    );

    let rep_dst: Eid = "dtn://replicate/inbox".parse().unwrap();
    let mut rep_bundle = build_bundle(&src_eid, &rep_dst, b"rep");
    assert_eq!(
        sink.dispatch(Some(&src_node), None, &mut rep_bundle)
            .await
            .unwrap(),
        Acceptance::Accepted
    );

    let mut fwd = Vec::new();
    for _ in 0..2 {
        let item = timeout(Duration::from_secs(3), forwarded_rx.recv())
            .await
            .expect("forward timeout")
            .expect("forwarded channel");
        fwd.push(item);
    }

    assert!(
        fwd.contains(&("dtn://peer_a/".to_string(), fb_dst)),
        "expected FALLBACK bundle on peer_a, got {fwd:?}"
    );
    assert!(
        fwd.contains(&("dtn://peer_b/".to_string(), rep_dst)),
        "expected FORWARD_REPLICATE bundle on peer_b, got {fwd:?}"
    );

    bpa.shutdown().await;
}
