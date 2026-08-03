//! A name the network says has no addresses is a host to investigate, not a reason to reject the request:
//! the plan names it per target, the summary names it beside the records the rest of the scan produced.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use rastreo_core::{HickoryResolver, RastreoError, ResolvedTarget, Resolver, Target};
use rastreo_server::build_app;
use rastreo_server::state::AppState;
use serde_json::json;

struct AddresslessName;

#[async_trait::async_trait]
impl Resolver for AddresslessName {
    async fn resolve(&self, target: &Target) -> Result<Vec<ResolvedTarget>, RastreoError> {
        match target {
            Target::Ip(addr) => Ok(vec![ResolvedTarget {
                ip: *addr,
                original: target.clone(),
                resolved_at: SystemTime::now(),
            }]),
            _ => Ok(Vec::new()),
        }
    }
}

async fn spawn(resolver: Arc<dyn Resolver>) -> SocketAddr {
    let app = build_app(AppState::new(resolver));
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind server");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

fn body() -> serde_json::Value {
    json!({
        "targets": [{"Ip": "127.0.0.1"}, {"DnsName": "stale.lab"}],
        "probers": [{"type": "tcp_connect", "ports": [9]}],
        "timeout_ms": 300,
    })
}

async fn post(addr: SocketAddr, path: &str) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .json(&body())
        .send()
        .await
        .expect("send");
    let status = resp.status();
    (status, resp.json().await.expect("body json"))
}

#[tokio::test]
async fn post_scans_dry_run_plans_a_target_with_no_addresses_as_unresolvable() {
    let addr = spawn(Arc::new(AddresslessName)).await;
    let (status, plan) = post(addr, "/scans?dry_run=true").await;

    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(plan["targets"][1]["resolution"], "unresolvable");
    assert_eq!(
        plan["total_probes"], 1,
        "the resolvable target is still planned: {plan}"
    );
    assert!(
        plan.get("refusal").is_none(),
        "a target with no addresses is not a refusal: {plan}"
    );
}

#[tokio::test]
async fn post_scans_names_the_targets_the_dry_run_planned_as_unresolvable() {
    let addr = spawn(Arc::new(AddresslessName)).await;
    let (plan_status, plan) = post(addr, "/scans?dry_run=true").await;
    let (scan_status, scan) = post(addr, "/scans").await;

    assert_eq!(plan_status, reqwest::StatusCode::OK);
    assert_eq!(scan_status, reqwest::StatusCode::OK);

    let planned: Vec<&str> = plan["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .filter(|entry| entry["resolution"] == "unresolvable")
        .map(|entry| entry["target"].as_str().expect("target string"))
        .collect();
    let summarized: Vec<&str> = scan["summary"]["unresolvable_targets"]
        .as_array()
        .expect("unresolvable_targets array")
        .iter()
        .map(|value| value.as_str().expect("target string"))
        .collect();

    assert_eq!(planned, vec!["stale.lab"]);
    assert_eq!(
        planned, summarized,
        "the two surfaces name the target the same way, in the same order"
    );
    assert_eq!(scan["summary"]["targets_resolved"], 1);
}

#[tokio::test]
async fn post_scans_dry_run_rejects_an_over_cap_target_with_the_status_the_scan_would() {
    let resolver: Arc<dyn Resolver> = Arc::new(
        HickoryResolver::from_system()
            .expect("system resolver")
            .with_limit(8),
    );
    let addr = spawn(resolver).await;
    let over_cap = json!({
        "targets": [{"Cidr": "10.0.0.0/24"}],
        "probers": [{"type": "tcp_connect", "ports": [22]}],
        "timeout_ms": 300,
    });

    let mut statuses = Vec::new();
    for path in ["/scans?dry_run=true", "/scans"] {
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}{path}"))
            .json(&over_cap)
            .send()
            .await
            .expect("send");
        statuses.push(resp.status());
    }
    assert_eq!(
        statuses,
        vec![
            reqwest::StatusCode::BAD_REQUEST,
            reqwest::StatusCode::BAD_REQUEST
        ],
        "the rehearsal answers what the scan answers"
    );
}
