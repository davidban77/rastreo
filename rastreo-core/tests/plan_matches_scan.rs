//! The plan a dry-run reports and the scan it rehearses read one resolution, so the counts they
//! publish are checkable against each other rather than maintained in parallel.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use rastreo_core::config::{BaseProbeConfig, DiscoverScenarioConfig};
use rastreo_core::{
    resolve_scenario, run_discovery, DiscoveryPlan, DiscoverySummary, HickoryResolver, MemorySink,
    MemorySinkHandle, PlanKnobs, ProberConfig, RastreoError, Resolver, RunOptions, Sink,
    SinkConfig, Target,
};

const CLOSED_PORT: u16 = 9;

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn cidr(s: &str) -> Target {
    Target::Cidr(s.parse().expect("cidr"))
}

// Two passes of the same prober: the plan's multiplication by prober count is exercised without a
// second protocol's timing.
fn scenario(targets: Vec<Target>) -> DiscoverScenarioConfig {
    let mut base = BaseProbeConfig::new();
    base.sink = Some(SinkConfig::Memory);
    base.timeout_ms = Some(200);
    DiscoverScenarioConfig::new(
        base,
        targets,
        vec![
            ProberConfig::TcpConnect {
                ports: vec![CLOSED_PORT],
            },
            ProberConfig::TcpConnect {
                ports: vec![CLOSED_PORT],
            },
        ],
    )
}

fn knobs() -> PlanKnobs {
    PlanKnobs {
        max_concurrent: 16,
        probe_rate: None,
        retries: 0,
        timeout_ms: 200,
    }
}

async fn rehearse_then_scan(
    resolver: Arc<dyn Resolver>,
    targets: Vec<Target>,
) -> (
    DiscoveryPlan,
    Result<DiscoverySummary, RastreoError>,
    MemorySinkHandle,
) {
    let scenario = scenario(targets);
    let resolution = resolve_scenario(resolver.as_ref(), &scenario.targets).await;
    let plan = DiscoveryPlan::resolved("agreement".to_string(), &scenario, &resolution, knobs())
        .expect("the scenario is valid, so it has a plan");
    let sink = MemorySink::new();
    let handle = sink.handle();
    let summary = run_discovery(
        RunOptions::new(&scenario)
            .resolver(resolver)
            .sink(Box::new(sink) as Box<dyn Sink>),
    )
    .await;
    (plan, summary, handle)
}

fn system_resolver(limit: Option<usize>) -> Arc<dyn Resolver> {
    let resolver = HickoryResolver::from_system().expect("system resolver");
    Arc::new(match limit {
        Some(limit) => resolver.with_limit(limit),
        None => resolver,
    })
}

#[tokio::test]
async fn the_plan_counts_the_probes_the_scan_performs() {
    let target_sets = vec![
        vec![cidr("127.0.0.0/30")],
        vec![cidr("127.0.0.0/30"), Target::Ip(ip(127, 0, 0, 1))],
        vec![Target::Ip(ip(127, 0, 0, 1)), Target::Ip(ip(127, 0, 0, 1))],
        vec![Target::Range {
            start: ip(127, 0, 0, 1),
            end: ip(127, 0, 0, 3),
        }],
    ];
    for targets in target_sets {
        let (plan, summary, _) = rehearse_then_scan(system_resolver(None), targets.clone()).await;
        let summary = summary.expect("every target resolves, so the scan runs");
        assert_eq!(
            plan.total_probes, summary.probe_attempts,
            "{targets:?}: the plan promised {} probes and the scan performed {}",
            plan.total_probes, summary.probe_attempts
        );
    }
}

#[tokio::test]
async fn the_plan_counts_the_hosts_the_scan_resolves() {
    let targets = vec![cidr("127.0.0.0/30"), Target::Ip(ip(127, 0, 0, 1))];
    let (plan, summary, _) = rehearse_then_scan(system_resolver(None), targets).await;
    let summary = summary.expect("every target resolves, so the scan runs");
    assert_eq!(summary.targets_resolved, 3);
    assert_eq!(plan.total_probes, summary.targets_resolved * 2);
}

#[tokio::test]
async fn a_scan_that_aborts_is_planned_as_probing_nothing() {
    let targets = vec![Target::Ip(ip(127, 0, 0, 1)), cidr("127.0.0.0/24")];
    let (plan, summary, handle) = rehearse_then_scan(system_resolver(Some(8)), targets).await;
    let err = summary.expect_err("an over-limit target aborts the scan");
    assert_eq!(plan.total_probes, 0);
    assert_eq!(plan.refusal, Some(err.to_string()));
    assert!(
        handle.bytes().is_empty(),
        "a scan the plan counted at zero must emit nothing"
    );
}

#[tokio::test]
async fn a_target_the_scan_never_reaches_is_still_attributed() {
    let targets = vec![Target::Ip(ip(127, 0, 0, 1)), cidr("127.0.0.0/24")];
    let (plan, _, _) = rehearse_then_scan(system_resolver(Some(8)), targets).await;
    assert_eq!(plan.targets.len(), 2);
    let rendered = plan.to_string();
    assert!(rendered.contains("127.0.0.1 → 127.0.0.1"), "{rendered}");
    assert!(rendered.contains("127.0.0.0/24 → <error:"), "{rendered}");
}
