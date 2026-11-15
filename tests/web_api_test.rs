//! Web API, SQLite persistence, and PBAC integration tests using `TestServerBuilder`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use dtnpm_mod_rego_routing::{BlacklistEntry, RegoRoutingModule};
use dtnpm_web_core::TestServerBuilder;
use serde_json::Value;

#[tokio::test]
async fn web_api_blacklist_policy_and_decisions_lifecycle() {
    let module = Arc::new(RegoRoutingModule::new().expect("create module"));
    let srv = TestServerBuilder::new()
        .node_id("dtn://node-a/")
        .callsign("F4TEST-1")
        .with_module(module.clone())
        .build()
        .await
        .expect("build test server");

    // 1. Capabilities expose rego_routing
    let caps_res = srv.get("/api/capabilities").await;
    assert_eq!(caps_res.status(), StatusCode::OK);
    let caps_bytes = axum::body::to_bytes(caps_res.into_body(), 1024 * 1024)
        .await
        .expect("caps body");
    let caps: Value = serde_json::from_slice(&caps_bytes).expect("caps json");
    assert_eq!(caps["modules"][0]["id"], "rego_routing");

    // 2. Reject invalid EID pattern without scheme
    let bad_bl = srv
        .post_json(
            "/api/rego_routing/v1/blacklist",
            serde_json::json!({ "eid_pattern": "not-an-eid", "reason": "bad" }),
        )
        .await;
    assert_eq!(bad_bl.status(), StatusCode::BAD_REQUEST);

    // 3. Create valid blacklist entry -> 201 Created and live engine updated
    let add_bl = srv
        .post_json(
            "/api/rego_routing/v1/blacklist",
            serde_json::json!({ "eid_pattern": "dtn://spam/*", "reason": "Spam beacon" }),
        )
        .await;
    assert_eq!(add_bl.status(), StatusCode::CREATED);
    let created_bytes = axum::body::to_bytes(add_bl.into_body(), 1024 * 1024)
        .await
        .expect("created body");
    let created: BlacklistEntry = serde_json::from_slice(&created_bytes).expect("entry json");
    assert_eq!(created.eid_pattern, "dtn://spam/*");
    assert!(created.enabled);
    assert_eq!(module.engine().blacklist().len(), 1);

    // 4. Duplicate pattern -> 409 Conflict
    let dup_bl = srv
        .post_json(
            "/api/rego_routing/v1/blacklist",
            serde_json::json!({ "eid_pattern": "dtn://spam/*", "reason": "Duplicate" }),
        )
        .await;
    assert_eq!(dup_bl.status(), StatusCode::CONFLICT);

    // 5. Toggle blacklist entry via PATCH -> disabled
    let patch_req = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/api/rego_routing/v1/blacklist/{}", created.id))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "enabled": false }).to_string(),
        ))
        .expect("build patch");
    let patch_res = srv.oneshot(patch_req).await;
    assert_eq!(patch_res.status(), StatusCode::OK);
    assert!(!module.engine().blacklist()[0].enabled);

    // 6. Delete blacklist entry via DELETE -> 204 No Content
    let del_req = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/api/rego_routing/v1/blacklist/{}", created.id))
        .body(Body::empty())
        .expect("build delete");
    let del_res = srv.oneshot(del_req).await;
    assert_eq!(del_res.status(), StatusCode::NO_CONTENT);
    assert!(module.engine().blacklist().is_empty());

    // 7. Invalid custom Rego policy rejected with 400 BAD_REQUEST
    let bad_pol_req = Request::builder()
        .method(Method::PUT)
        .uri("/api/rego_routing/v1/policy")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "custom_ingress_rego": "package dtn.ingress\nthis is invalid rego {{{"
            })
            .to_string(),
        ))
        .expect("build bad policy req");
    let bad_pol_res = srv.oneshot(bad_pol_req).await;
    assert_eq!(bad_pol_res.status(), StatusCode::BAD_REQUEST);

    // 8. Valid custom policy & configurable TREB block type 205 persisted
    let ok_pol_req = Request::builder()
        .method(Method::PUT)
        .uri("/api/rego_routing/v1/policy")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "active_profile": "custom",
                "hop_limit": 12,
                "treb_block_type": 205
            })
            .to_string(),
        ))
        .expect("build ok policy req");
    let ok_pol_res = srv.oneshot(ok_pol_req).await;
    assert_eq!(ok_pol_res.status(), StatusCode::OK);
    assert_eq!(module.engine().config().hop_limit, 12);
    assert_eq!(module.engine().config().treb_block_type, 205);

    // 9. Decisions endpoint responds 200 OK
    let dec_res = srv.get("/api/rego_routing/v1/decisions").await;
    assert_eq!(dec_res.status(), StatusCode::OK);
}
