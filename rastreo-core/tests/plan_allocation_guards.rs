//! What it costs to plan a scan. A dry-run reports a bounded page of text, so it must allocate a
//! bounded amount of memory — whatever address space the specs cover.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;
use std::sync::Arc;

use rastreo_core::config::{BaseProbeConfig, DiscoverScenarioConfig};
use rastreo_core::{
    resolve_scenario, ClassifierConfig, DiscoveryPlan, GuardedResolver, HickoryResolver, PlanKnobs,
    ProberConfig, Resolver, RunOptions, SinkConfig, Target, TargetResolution,
};
use tokio::runtime::Runtime;

thread_local! {
    static ALLOC_COUNT: Cell<u64> = const { Cell::new(0) };
    static ALLOC_BYTES: Cell<u64> = const { Cell::new(0) };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOC_COUNT.try_with(|c| c.set(c.get() + 1));
        let _ = ALLOC_BYTES.try_with(|c| c.set(c.get() + layout.size() as u64));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Allocations {
    count: u64,
    bytes: u64,
}

fn measure(body: impl FnOnce()) -> Allocations {
    ALLOC_COUNT.with(|c| c.set(0));
    ALLOC_BYTES.with(|c| c.set(0));
    body();
    Allocations {
        count: ALLOC_COUNT.with(Cell::get),
        bytes: ALLOC_BYTES.with(Cell::get),
    }
}

const SPECS: u8 = 10;

// Non-overlapping specs written in the same number of characters, so the target render costs the
// same whatever the block covers; `noop` keeps the default rule tables' megabytes of regex — the
// same megabytes at every prefix length — from drowning the figure.
fn scenario(prefix_len: u8) -> DiscoverScenarioConfig {
    let mut base = BaseProbeConfig::new();
    base.sink = Some(SinkConfig::Stdout);
    base.classifier = Some(ClassifierConfig::Noop);
    let targets = (0..SPECS)
        .map(|i| Target::Cidr(format!("10.{i}.0.0/{prefix_len}").parse().expect("cidr")))
        .collect();
    DiscoverScenarioConfig::new(
        base,
        targets,
        vec![ProberConfig::TcpConnect { ports: vec![22] }],
    )
}

fn knobs() -> PlanKnobs {
    PlanKnobs {
        max_concurrent: 64,
        probe_rate: None,
        retries: 0,
        timeout_ms: 1000,
    }
}

fn plan_cost(
    rt: &Runtime,
    resolver: &dyn Resolver,
    scenario: &DiscoverScenarioConfig,
) -> Allocations {
    // Warm every lazily-initialised allocation the first plan makes, so the measured pass is the plan alone.
    rt.block_on(plan_once(resolver, scenario));
    measure(|| {
        black_box(rt.block_on(plan_once(resolver, scenario)));
    })
}

async fn plan_once(resolver: &dyn Resolver, scenario: &DiscoverScenarioConfig) -> DiscoveryPlan {
    let resolution = resolve_scenario(resolver, &scenario.targets).await;
    RunOptions::new(scenario)
        .plan("cost".to_string(), knobs())
        .await
        .expect("the scenario is valid, so it has a plan")
        .resolve(&resolution)
}

fn system_resolver() -> HickoryResolver {
    HickoryResolver::from_system().expect("system resolver")
}

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

#[test]
fn planning_a_scan_costs_the_same_whatever_address_space_its_specs_cover() {
    let rt = runtime();
    let resolver = system_resolver();

    let narrow = plan_cost(&rt, &resolver, &scenario(24));
    let wide = plan_cost(&rt, &resolver, &scenario(17));

    assert_eq!(
        narrow, wide,
        "ten /17 specs cover 129× the addresses of ten /24s and must cost the same to plan"
    );
    assert!(
        wide.bytes < 64 * 1024,
        "a plan is a page of text, not an address space: {wide:?}"
    );
}

#[test]
fn planning_a_refused_scan_costs_the_same_whatever_address_space_its_specs_cover() {
    let rt = runtime();
    // Each cap sits between one spec and the sum of ten, so the set is refused in aggregate while
    // every target still re-plans on its own to say which one earned the refusal.
    let capped = |scenario: &DiscoverScenarioConfig, cap: usize| {
        let guard = GuardedResolver::new(Arc::new(system_resolver()), None, Some(cap));
        let plan = rt.block_on(plan_once(&guard, scenario));
        assert!(
            plan.refusal.is_some(),
            "the aggregate cap must refuse this set, or the test measures the wrong path"
        );
        assert!(
            plan.targets
                .iter()
                .all(|t| matches!(t.resolution, TargetResolution::Resolved(_))),
            "every target is under the cap on its own, so each is attributed rather than refused"
        );
        plan_cost(&rt, &guard, scenario)
    };

    let narrow = capped(&scenario(24), 1_000);
    let wide = capped(&scenario(17), 100_000);

    assert_eq!(
        narrow.count, wide.count,
        "attributing a refusal must sample each target, not expand it"
    );
    // The refusal names the host count and the cap, so the wider set writes a few more digits.
    assert!(
        wide.bytes.abs_diff(narrow.bytes) < 1_024,
        "129× the addresses cost {} extra bytes to plan",
        wide.bytes.abs_diff(narrow.bytes)
    );
    assert!(
        wide.bytes < 64 * 1024,
        "a refused plan carries a count and a refusal, nothing wider: {wide:?}"
    );
}
