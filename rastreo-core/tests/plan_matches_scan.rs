//! The plan a dry-run reports and the scan it rehearses read one resolution, so what they publish —
//! the counts, and the addresses behind them — is checkable against each other rather than
//! maintained in parallel.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::SystemTime;

use rastreo_core::config::{BaseProbeConfig, DiscoverScenarioConfig};
use rastreo_core::{
    resolve_scenario, run_discovery, DeviceRecord, DiscoveryPlan, DiscoverySummary, FuserConfig,
    HickoryResolver, MemorySink, MemorySinkHandle, PlanKnobs, ProberConfig, RastreoError,
    ResolvedTarget, Resolver, RunOptions, Sink, SinkConfig, SinkType, Target, TargetResolution,
    SAMPLED_ADDRESSES,
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

// A closed port is still a record to emit, so every address the scan reached is nameable from the sink.
fn emitting_scenario(targets: Vec<Target>) -> DiscoverScenarioConfig {
    let mut scenario = scenario(targets);
    scenario.base.fuser = Some(FuserConfig::Direct {
        include_unreachable: Some(true),
        confidence_baseline: None,
        confidence_per_signal: None,
    });
    scenario
}

async fn rehearse_then_scan(
    resolver: Arc<dyn Resolver>,
    targets: Vec<Target>,
) -> (
    DiscoveryPlan,
    Result<DiscoverySummary, RastreoError>,
    MemorySinkHandle,
) {
    rehearse_then_scan_with(resolver, scenario(targets)).await
}

async fn rehearse_then_scan_with(
    resolver: Arc<dyn Resolver>,
    scenario: DiscoverScenarioConfig,
) -> (
    DiscoveryPlan,
    Result<DiscoverySummary, RastreoError>,
    MemorySinkHandle,
) {
    let resolution = resolve_scenario(resolver.as_ref(), &scenario.targets).await;
    let sink = MemorySink::new();
    let handle = sink.handle();
    let opts = RunOptions::new(&scenario)
        .resolver(resolver)
        .sink(Box::new(sink) as Box<dyn Sink>);
    let plan = opts
        .plan("agreement".to_string(), knobs())
        .await
        .expect("the scenario is valid, so it has a plan")
        .resolve(&resolution);
    let summary = run_discovery(opts).await;
    (plan, summary, handle)
}

fn system_resolver(limit: Option<usize>) -> Arc<dyn Resolver> {
    let resolver = HickoryResolver::from_system().expect("system resolver");
    Arc::new(match limit {
        Some(limit) => resolver.with_limit(limit),
        None => resolver,
    })
}

type Answers = Vec<(Target, Vec<IpAddr>)>;

// The rehearsal and the run resolve independently, so a live name would make this family flaky here.
struct ScriptedNames {
    answers: Answers,
}

#[async_trait::async_trait]
impl Resolver for ScriptedNames {
    async fn resolve(&self, target: &Target) -> Result<Vec<ResolvedTarget>, RastreoError> {
        let ips = match self.answers.iter().find(|(scripted, _)| scripted == target) {
            Some((scripted, ips)) => {
                assert!(
                    matches!(scripted, Target::DnsName(_)),
                    "this fixture scripts names only; a block form would be answered as a point set, \
                     which is a shape no resolver produces for it: {scripted:?}"
                );
                ips.clone()
            }
            None => match target {
                Target::Ip(addr) => vec![*addr],
                _ => panic!(
                    "this fixture answers scripted names and single addresses only: {target:?}"
                ),
            },
        };
        let resolved_at = SystemTime::now();
        Ok(ips
            .into_iter()
            .map(|ip| ResolvedTarget {
                ip,
                original: target.clone(),
                resolved_at,
            })
            .collect())
    }
}

fn scripted_resolver(answers: Answers) -> Arc<dyn Resolver> {
    Arc::new(ScriptedNames { answers })
}

fn stale_name_resolver(stale: Vec<Target>) -> Arc<dyn Resolver> {
    scripted_resolver(stale.into_iter().map(|name| (name, Vec::new())).collect())
}

fn dns(name: &str) -> Target {
    Target::DnsName(name.to_string())
}

#[tokio::test]
async fn a_target_with_no_addresses_is_named_by_the_plan_and_by_the_summary_alike() {
    let stale = dns("stale.lab");
    let targets = vec![Target::Ip(ip(127, 0, 0, 1)), stale.clone()];
    let (plan, summary, _) = rehearse_then_scan(stale_name_resolver(vec![stale]), targets).await;
    let summary = summary.expect("one nameless target does not abandon the scan");

    assert_eq!(summary.unresolvable_targets, vec!["stale.lab".to_string()]);
    let planned: Vec<&str> = plan
        .targets
        .iter()
        .filter(|planned| matches!(planned.resolution, TargetResolution::Unresolvable))
        .map(|planned| planned.target.as_str())
        .collect();
    assert_eq!(
        planned, summary.unresolvable_targets,
        "a caller holding a plan and a summary reconciles them by the target as written"
    );
    assert!(plan.refusal.is_none(), "a skipped target is not a refusal");
}

#[tokio::test]
async fn the_plan_counts_the_probes_the_scan_performs_beside_a_target_with_no_addresses() {
    let stale = dns("stale.lab");
    let targets = vec![
        Target::Ip(ip(127, 0, 0, 1)),
        stale.clone(),
        Target::Ip(ip(127, 0, 0, 2)),
    ];
    let (plan, summary, _) = rehearse_then_scan(stale_name_resolver(vec![stale]), targets).await;
    let summary = summary.expect("the resolvable targets are still probed");

    assert_eq!(summary.targets_resolved, 2);
    assert_eq!(plan.total_probes, 4, "2 addresses × 2 prober passes");
    assert_eq!(plan.total_probes, summary.probe_attempts);
}

#[tokio::test]
async fn a_scan_whose_every_target_has_no_addresses_completes_having_probed_nothing() {
    let targets = vec![dns("stale.lab"), dns("gone.lab")];
    let (plan, summary, handle) =
        rehearse_then_scan(stale_name_resolver(targets.clone()), targets).await;
    let summary = summary.expect("a scan with nothing to probe is not a failed scan");

    assert_eq!(plan.total_probes, 0);
    assert!(
        plan.refusal.is_none(),
        "nothing to probe is not something the resolver refused: {plan:?}"
    );
    assert_eq!(summary.probe_attempts, 0);
    assert_eq!(
        summary.unresolvable_targets,
        vec!["stale.lab".to_string(), "gone.lab".to_string()]
    );
    assert!(handle.bytes().is_empty());
}

#[tokio::test]
async fn the_plan_counts_the_probes_the_scan_performs_for_names_that_resolve() {
    let cases: Vec<(Answers, Vec<Target>, usize)> = vec![
        (
            vec![(
                dns("three.lab"),
                vec![ip(127, 0, 0, 1), ip(127, 0, 0, 2), ip(127, 0, 0, 3)],
            )],
            vec![dns("three.lab")],
            3,
        ),
        (
            vec![(dns("one.lab"), vec![ip(127, 0, 0, 4)])],
            vec![dns("one.lab"), Target::Ip(ip(127, 0, 0, 5))],
            2,
        ),
        (
            vec![(dns("shared.lab"), vec![ip(127, 0, 0, 6)])],
            vec![dns("shared.lab"), Target::Ip(ip(127, 0, 0, 6))],
            2,
        ),
        (
            vec![
                (dns("first.lab"), vec![ip(127, 0, 0, 7)]),
                (dns("second.lab"), vec![ip(127, 0, 0, 7)]),
            ],
            vec![dns("first.lab"), dns("second.lab")],
            2,
        ),
        // A caller's own resolver may repeat an address; `HickoryResolver` never does.
        (
            vec![(dns("twice.lab"), vec![ip(127, 0, 0, 8), ip(127, 0, 0, 8)])],
            vec![dns("twice.lab")],
            2,
        ),
        (
            vec![
                (dns("live.lab"), vec![ip(127, 0, 0, 9)]),
                (dns("gone.lab"), Vec::new()),
            ],
            vec![dns("live.lab"), dns("gone.lab")],
            1,
        ),
    ];
    for (answers, targets, addresses) in cases {
        let (plan, summary, _) =
            rehearse_then_scan(scripted_resolver(answers), targets.clone()).await;
        let summary = summary.expect("a scripted name does not abandon the scan");
        assert_eq!(
            summary.targets_resolved, addresses,
            "{targets:?}: the plan counted the addresses the names answered with"
        );
        assert_eq!(
            plan.total_probes,
            addresses * 2,
            "{targets:?}: 2 prober passes per address"
        );
        assert_eq!(
            plan.total_probes, summary.probe_attempts,
            "{targets:?}: the plan promised {} probes and the scan performed {}",
            plan.total_probes, summary.probe_attempts
        );
    }
}

#[tokio::test]
async fn a_name_with_more_addresses_than_the_plan_samples_is_counted_in_full() {
    let name = dns("fleet.lab");
    let addresses: Vec<IpAddr> = (1..=8).map(|last| ip(127, 0, 1, last)).collect();
    let (plan, summary, _) = rehearse_then_scan(
        scripted_resolver(vec![(name.clone(), addresses.clone())]),
        vec![name],
    )
    .await;
    let summary = summary.expect("the name resolves, so the scan runs");

    let TargetResolution::Resolved(attributed) = &plan.targets[0].resolution else {
        panic!("the name resolves: {:?}", plan.targets[0].resolution);
    };
    assert_eq!(attributed.total, addresses.len());
    assert_eq!(attributed.sample, addresses[..SAMPLED_ADDRESSES]);
    assert_eq!(summary.targets_resolved, addresses.len());
    assert_eq!(
        plan.total_probes, summary.probe_attempts,
        "the sample the plan renders is not the count it promises"
    );
}

#[tokio::test]
async fn the_addresses_the_plan_names_for_a_resolving_name_are_the_ones_the_scan_probes() {
    let name = dns("router.lab");
    let addresses = vec![ip(127, 0, 2, 1), ip(127, 0, 2, 2), ip(127, 0, 2, 3)];
    let (plan, summary, handle) = rehearse_then_scan_with(
        scripted_resolver(vec![(name.clone(), addresses.clone())]),
        emitting_scenario(vec![name]),
    )
    .await;
    summary.expect("the name resolves, so the scan runs");

    let TargetResolution::Resolved(attributed) = &plan.targets[0].resolution else {
        panic!("the name resolves: {:?}", plan.targets[0].resolution);
    };
    let probed: Vec<IpAddr> = handle
        .ndjson_lines()
        .iter()
        .map(|line| {
            serde_json::from_str::<DeviceRecord>(line)
                .expect("a device record")
                .mgmt_ip
                .expect("a record the scan probed by address")
        })
        .collect();
    assert_eq!(
        probed, attributed.sample,
        "a plan that names addresses the scan never reaches is a plan that lies"
    );
}

#[tokio::test]
async fn a_name_that_resolves_is_not_named_among_the_targets_with_no_addresses() {
    let live = dns("live.lab");
    let gone = dns("gone.lab");
    let (plan, summary, _) = rehearse_then_scan(
        scripted_resolver(vec![
            (live.clone(), vec![ip(127, 0, 3, 1)]),
            (gone.clone(), Vec::new()),
        ]),
        vec![live, gone],
    )
    .await;
    let summary = summary.expect("one nameless target does not abandon the scan");

    assert_eq!(summary.unresolvable_targets, vec!["gone.lab".to_string()]);
    assert!(matches!(
        plan.targets[0].resolution,
        TargetResolution::Resolved(_)
    ));
    assert!(matches!(
        plan.targets[1].resolution,
        TargetResolution::Unresolvable
    ));
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

#[tokio::test]
async fn a_plan_for_an_injected_sink_names_the_destination_the_scan_writes_to() {
    let mut scenario = scenario(vec![Target::Ip(ip(127, 0, 0, 1))]);
    scenario.base.sink = Some(SinkConfig::File {
        path: "/tmp/never-written.ndjson".into(),
    });
    // A closed port is still a record to emit, so the destination has something to receive.
    scenario.base.fuser = Some(FuserConfig::Direct {
        include_unreachable: Some(true),
        confidence_baseline: None,
        confidence_per_signal: None,
    });
    let resolver = system_resolver(None);
    let resolution = resolve_scenario(resolver.as_ref(), &scenario.targets).await;

    let sink = MemorySink::new();
    let handle = sink.handle();
    let opts = RunOptions::new(&scenario)
        .resolver(resolver)
        .sink(Box::new(sink) as Box<dyn Sink>);
    let plan = opts
        .plan("agreement".to_string(), knobs())
        .await
        .expect("the scenario is valid, so it has a plan")
        .resolve(&resolution);
    let summary = run_discovery(opts)
        .await
        .expect("the target resolves, so the scan runs");

    assert_eq!(
        plan.sink,
        SinkType::Memory.as_label(),
        "the plan must name the injected sink, not the scenario's discarded one",
    );
    assert_eq!(summary.sink_type, Some(SinkType::Memory));
    assert!(
        !handle.bytes().is_empty(),
        "the destination the plan named is the one that received records",
    );
}
