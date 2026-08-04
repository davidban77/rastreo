use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch, Semaphore};
use tracing::Instrument;

use crate::checkpoint::{resume_fingerprint, Checkpoint, CheckpointConfig, CheckpointWriter};
use crate::classifier::{create_classifier, Classifier};
use crate::collection_profile::CollectionProfileAssembler;
use crate::config::DiscoverScenarioConfig;
use crate::encoder::{create_encoder, ensure_encoder_output_fits_sink, Encoder};
use crate::error::{ProbeErrorKind, RastreoError};
use crate::fuser::{create_fuser, Fuser};
use crate::model::{
    DeviceRecord, ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome, ResolvedTarget, ScanMetadata,
    PROBE_KIND_COUNT,
};
use crate::plan::{PlanKnobs, ScenarioPlan};
use crate::prober::{create_prober, Prober};
use crate::resolver::{HickoryResolver, ResolvedPlan, Resolver};
use crate::scheduler::{BoundedScheduler, Scheduler, TargetScan};
use crate::sink::{create_sink, RecordKind, Sink, SinkConfig, SinkErrorClass, SinkType};
use crate::topology::TopologyAssembler;

const DEFAULT_TIMEOUT_MS: u64 = 1000;
const DEFAULT_CONCURRENCY: u32 = 64;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[non_exhaustive]
pub struct DiscoverySummary {
    pub targets_resolved: usize,
    pub probe_attempts: usize,
    pub records_emitted: usize,
    /// Topology links emitted on the second stream; `0` when no LLDP data was collected.
    #[serde(default)]
    pub links_emitted: usize,
    /// Collection profiles emitted on the second stream; `0` when no gNMI capability data was collected.
    #[serde(default)]
    pub profiles_emitted: usize,
    /// Targets that contributed no addresses, as written in the scenario and in input order; each
    /// was probed zero times. Empty when every target resolved.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolvable_targets: Vec<String>,
    /// Faulted probes tallied by fault kind; empty when no probe faulted.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub error_counts: BTreeMap<ProbeErrorKind, usize>,
    /// Per-probe-kind attempted / errored breakdown; empty when no probes ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probes_by_kind: Vec<ProbeKindSummary>,
    /// Records delivered to a DLQ destination during this scan.
    #[serde(default)]
    pub dlq_records: usize,
    /// DLQ deliveries keyed by `(destination sink type, failure class)`; empty when nothing was quarantined.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dlq_records_by_type_and_class: Vec<(SinkType, SinkErrorClass, u64)>,
    /// Concrete sink kind the scan wrote against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink_type: Option<SinkType>,
    /// True when the run terminated early via the cancellation token; counters reflect partial progress.
    #[serde(default)]
    pub cancelled: bool,
    /// Kind and sample detail of the first probe that faulted; latched once per scan, absent when no probe faulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_probe_error: Option<ProbeFault>,
    /// Milliseconds one scan took; on a summary folding several, the sum of their durations.
    #[serde(rename = "elapsed_ms", serialize_with = "serialize_duration_as_millis")]
    #[schemars(with = "u64", rename = "elapsed_ms")]
    pub elapsed: Duration,
}

/// A running snapshot of an in-flight scan, published on each target drain.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct DiscoveryProgress {
    pub targets_completed: usize,
    pub targets_total: usize,
    pub records_emitted: usize,
    pub probe_attempts: usize,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[non_exhaustive]
pub struct ProbeKindSummary {
    pub kind: ProbeKind,
    pub attempted: usize,
    pub errored: usize,
}

fn serialize_duration_as_millis<S: serde::Serializer>(
    d: &Duration,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u128(d.as_millis())
}

/// Knobs for [`run_discovery`]; only the scenario is required, each setter overrides its default.
#[must_use]
pub struct RunOptions<'a> {
    scenario: &'a DiscoverScenarioConfig,
    resolver: Option<Arc<dyn Resolver>>,
    sink: Option<Box<dyn Sink>>,
    cancel: Option<watch::Receiver<bool>>,
    progress: Option<watch::Sender<DiscoveryProgress>>,
    checkpoint: Option<CheckpointConfig>,
}

impl<'a> RunOptions<'a> {
    pub fn new(scenario: &'a DiscoverScenarioConfig) -> Self {
        Self {
            scenario,
            resolver: None,
            sink: None,
            cancel: None,
            progress: None,
            checkpoint: None,
        }
    }

    pub fn resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Overrides the scenario's own sink.
    pub fn sink(mut self, sink: Box<dyn Sink>) -> Self {
        self.sink = Some(sink);
        self
    }

    pub fn cancel(mut self, cancel: watch::Receiver<bool>) -> Self {
        self.cancel = Some(cancel);
        self
    }

    pub fn progress(mut self, progress: watch::Sender<DiscoveryProgress>) -> Self {
        self.progress = Some(progress);
        self
    }

    pub fn checkpoint(mut self, checkpoint: CheckpointConfig) -> Self {
        self.checkpoint = Some(checkpoint);
        self
    }

    /// Render the stages a run with these options resolves to. The destination is read off the sink
    /// this run would write to, so a plan cannot name one the run discards.
    pub async fn plan(
        &self,
        label: String,
        knobs: PlanKnobs,
    ) -> Result<ScenarioPlan, RastreoError> {
        let destinations = match &self.sink {
            Some(sink) => Some(sink.destinations().await),
            None => None,
        };
        ScenarioPlan::build(label, self.scenario, knobs, destinations.as_deref())
    }
}

/// Run a discovery scan; unset [`RunOptions`] knobs default to the system resolver, the scenario's sink, and a never-firing cancel.
pub async fn run_discovery(opts: RunOptions<'_>) -> Result<DiscoverySummary, RastreoError> {
    let RunOptions {
        scenario,
        resolver,
        sink,
        cancel,
        progress,
        checkpoint,
    } = opts;

    // Preflight is read-only and must precede sink construction, which opens files and dials brokers.
    scenario.validate()?;
    let resume_from = match &checkpoint {
        Some(config) => crate::checkpoint::preflight_checkpoint_request(scenario, config)?,
        None => None,
    };
    let resolver = match resolver {
        Some(r) => r,
        None => Arc::new(HickoryResolver::from_system()?),
    };
    let sink = match sink {
        Some(s) => s,
        None => {
            let sink_config = scenario.base.sink.clone().unwrap_or(SinkConfig::Stdout);
            // Offline first: a broker sink is rejected before the connect, not after it.
            ensure_encoder_output_fits_sink(
                &scenario.effective_encoder_config(),
                sink_config.requires_structured_records(),
            )?;
            create_sink(&sink_config).await?
        }
    };
    let cancel = cancel.unwrap_or_else(|| watch::channel(false).1);
    run_discovery_core(
        scenario,
        resolver,
        sink,
        cancel,
        progress,
        checkpoint,
        resume_from,
    )
    .await
}

async fn run_discovery_core(
    scenario: &DiscoverScenarioConfig,
    resolver: Arc<dyn Resolver>,
    mut sink: Box<dyn Sink>,
    cancel: watch::Receiver<bool>,
    progress: Option<watch::Sender<DiscoveryProgress>>,
    checkpoint: Option<CheckpointConfig>,
    resume_from: Option<Checkpoint>,
) -> Result<DiscoverySummary, RastreoError> {
    let start = Instant::now();

    // Constant spans per scan: root + one per stage. Probe tasks are never spanned so a /16 stays zero-alloc.
    let scan_span = tracing::info_span!("scan", targets = tracing::field::Empty);

    // A resume rebuilds the plan from the checkpoint's pins (never re-resolving DNS) and restores the
    // prior run's scan identity, so resumed records group with the pre-crash records under one scan_id.
    let (scan_metadata, plan, resume_base) = match &resume_from {
        Some(checkpoint) => {
            let scan_metadata = Arc::new(ScanMetadata::resumed(
                scenario,
                checkpoint.scan_id.clone(),
                checkpoint.initiated_at,
            ));
            let plan = ResolvedPlan::from_pinned(&scenario.targets, &checkpoint.dns_pins)?;
            (scan_metadata, plan, checkpoint.highest_flushed_index)
        }
        None => {
            let scan_metadata = Arc::new(ScanMetadata::new(scenario));
            let plan = resolver
                .plan(&scenario.targets)
                .instrument(tracing::info_span!(parent: &scan_span, "resolve"))
                .await?;
            (scan_metadata, plan, 0usize)
        }
    };

    // Pre-flight count = the number of targets the stream yields (dedup dropped), so progress shows a
    // real denominator without materializing the address space.
    let targets_resolved = plan.total_hosts();
    scan_span.record("targets", targets_resolved as u64);

    let max_concurrent = scenario
        .base
        .max_concurrent
        .unwrap_or(DEFAULT_CONCURRENCY)
        .max(1) as usize;
    let scheduler = BoundedScheduler::new(max_concurrent).with_probe_rate(scenario.base.probe_rate);

    let timeout_ms = scenario.base.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    // One shared permit pool sized to the concurrency cap keeps total in-flight sockets at the same
    // fd envelope as a serial sweep, no matter how wide targets × ports grows.
    let port_budget = Arc::new(Semaphore::new(max_concurrent));
    let ctx = ProbeCtx::new(
        Duration::from_millis(timeout_ms),
        scenario.base.retries.unwrap_or(0),
    )
    .with_port_budget(Some(port_budget));

    let encoder_config = scenario.effective_encoder_config();
    // Catches a sink handed in through `RunOptions::sink`, which never passed the config check.
    ensure_encoder_output_fits_sink(&encoder_config, sink.requires_structured_records().await)?;
    let encoder = create_encoder(&encoder_config)?;

    let mut fuser = create_fuser(&scenario.effective_fuser_config())?;
    let classifier = create_classifier(&scenario.effective_classifier_config())?;

    let mut probers: Vec<Arc<dyn Prober>> = Vec::with_capacity(scenario.probers.len());
    for prober_config in &scenario.probers {
        probers.push(Arc::from(create_prober(prober_config)?));
    }

    // Read alongside the pins, before `into_stream` consumes the plan; these contribute nothing to it,
    // so `resume_base`'s skip arithmetic counts the same targets with or without them.
    let unresolvable_targets: Vec<String> = plan
        .unresolvable_targets()
        .iter()
        .map(ToString::to_string)
        .collect();

    // Built before `into_stream` consumes the plan: the DNS pins a resume replays are read off it here.
    // `resume_base` offsets recorded checkpoint indices to the global position of the continued scan.
    let checkpoint_writer = checkpoint.map(|config| {
        CheckpointWriter::new(
            config,
            &scan_metadata,
            resume_fingerprint(scenario),
            plan.dns_pins(),
        )
        .with_resume_base(resume_base)
    });

    // Skip the K already-done targets but re-probe the boundary target K itself (skip(K), not
    // skip(K+1)): K's records are durable, yet a torn final flush could have lost it — a boundary
    // duplicate is upserted downstream by identity_key, a gap loses a host for good.
    let stream: Box<dyn Iterator<Item = ResolvedTarget> + Send> = if resume_base > 0 {
        Box::new(plan.into_stream().skip(resume_base))
    } else {
        plan.into_stream()
    };

    let reorder_peak = AtomicUsize::new(0);
    let mut summary = stream_discovery(
        &scheduler,
        probers,
        stream,
        ctx,
        cancel,
        fuser.as_mut(),
        classifier.as_ref(),
        encoder.as_ref(),
        sink.as_mut(),
        &scan_metadata,
        targets_resolved,
        start,
        resume_base,
        &reorder_peak,
        &scan_span,
        progress.as_ref(),
        checkpoint_writer,
    )
    .await?;
    summary.unresolvable_targets = unresolvable_targets;
    Ok(summary)
}

#[derive(Default)]
struct ScanAccumulation {
    // Only the batch reference collects raw outcomes for `drive_fuser`; the streaming path fuses
    // each target as it arrives and never buffers the whole scan.
    #[cfg(test)]
    all_outcomes: Vec<ProbeOutcome>,
    probe_attempts: usize,
    error_counts: BTreeMap<ProbeErrorKind, usize>,
    first_probe_error: Option<ProbeFault>,
    attempts_by_kind: [usize; PROBE_KIND_COUNT],
    errors_by_kind: [usize; PROBE_KIND_COUNT],
    cancelled: bool,
}

// Target-outer iteration sees faults in a different order than a prober-outer loop, so
// `first_probe_error` tracks the smallest `(prober_pass_index, target_index)` key — the first
// fault a prober-outer scan would have latched. The key is order-independent, so accumulating in
// input-target order yields the same value.
fn accumulate_target(
    acc: &mut ScanAccumulation,
    prober_kinds: &[ProbeKind],
    scan: &TargetScan,
    best_key: &mut Option<(usize, usize)>,
) {
    let target_index = scan.target_index;
    for (pass_index, result) in &scan.outcomes {
        acc.probe_attempts += 1;
        let kind = prober_kinds[*pass_index];
        acc.attempts_by_kind[kind.index()] += 1;
        match result {
            Ok(outcome) => {
                if let Some(fault) = &outcome.fault {
                    acc.errors_by_kind[kind.index()] += 1;
                    *acc.error_counts.entry(fault.kind).or_insert(0) += 1;
                    let key = (*pass_index, target_index);
                    if best_key.is_none_or(|bk| key < bk) {
                        *best_key = Some(key);
                        acc.first_probe_error = Some(fault.clone());
                    }
                }
            }
            // A prober carries every fault as data on the outcome; a stray `Err` means it could
            // not attempt at all. Keep the contract total by counting it as `Other`.
            Err(err) => {
                acc.errors_by_kind[kind.index()] += 1;
                *acc.error_counts.entry(ProbeErrorKind::Other).or_insert(0) += 1;
                tracing::debug!(error = %err, "probe failed");
                let msg = err.to_string();
                if !msg.is_empty() {
                    let key = (*pass_index, target_index);
                    if best_key.is_none_or(|bk| key < bk) {
                        *best_key = Some(key);
                        acc.first_probe_error = Some(ProbeFault::new(ProbeErrorKind::Other, msg));
                    }
                }
            }
        }
    }
}

/// Delivers one encoded record, skipping the write when the encoder rendered nothing for this
/// kind. Returns whether anything was written, so callers count only what the sink received.
///
/// Exposed for `benches/emit_path.rs` and `tests/emit_path_guards.rs`; not part of the
/// supported API.
#[doc(hidden)]
pub async fn write_encoded(
    sink: &mut dyn Sink,
    kind: RecordKind,
    buf: &[u8],
) -> Result<bool, RastreoError> {
    if buf.is_empty() {
        return Ok(false);
    }
    sink.write_kind(kind, buf).await?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
async fn emit_target_records(
    outcomes: Vec<(usize, Result<ProbeOutcome, RastreoError>)>,
    fuser: &mut dyn Fuser,
    classifier: &dyn Classifier,
    encoder: &dyn Encoder,
    sink: &mut dyn Sink,
    scan_metadata: &Arc<ScanMetadata>,
    assembler: &mut TopologyAssembler,
    profile_assembler: &mut CollectionProfileAssembler,
    buf: &mut Vec<u8>,
    records_emitted: &mut usize,
    emit_err: &mut Option<RastreoError>,
) -> Result<(), RastreoError> {
    // Only Ok outcomes fuse into a record; a stray Err is tallied as a fault by metric
    // accumulation and carries nothing to emit.
    let probe_outcomes: Vec<ProbeOutcome> =
        outcomes.into_iter().filter_map(|(_, r)| r.ok()).collect();
    assembler.observe_outcomes(&probe_outcomes);
    profile_assembler.observe_outcomes(&probe_outcomes);
    let mut records = fuser.ingest(probe_outcomes)?;
    for record in &mut records {
        classifier.classify(record)?;
        stamp_scan_metadata(record, scan_metadata);
        assembler.observe_record(record);
        profile_assembler.observe_record(record);
    }
    for record in &records {
        buf.clear();
        if let Err(e) = encoder.encode_record(record, buf) {
            *emit_err = Some(e);
            break;
        }
        match write_encoded(sink, RecordKind::Device, buf).await {
            Ok(written) => *records_emitted += usize::from(written),
            Err(e) => {
                *emit_err = Some(e);
                break;
            }
        }
    }
    Ok(())
}

/// Streams each target's record the moment its scan completes: consumes `TargetScan`s in completion
/// order, reorders them by `target_index`, and emits each in input-target order. A bounded channel
/// backpressures the scan to the sink's pace, so the pipeline never holds the whole scan.
#[allow(clippy::too_many_arguments)]
async fn stream_discovery(
    scheduler: &BoundedScheduler,
    probers: Vec<Arc<dyn Prober>>,
    targets: Box<dyn Iterator<Item = ResolvedTarget> + Send>,
    ctx: ProbeCtx,
    cancel: watch::Receiver<bool>,
    fuser: &mut dyn Fuser,
    classifier: &dyn Classifier,
    encoder: &dyn Encoder,
    sink: &mut dyn Sink,
    scan_metadata: &Arc<ScanMetadata>,
    targets_resolved: usize,
    start: Instant,
    // A resumed run's scheduler restarts `target_index` at 0; `resume_base` maps local counts back to
    // the global position for progress reporting (the writer offsets its own recorded indices).
    resume_base: usize,
    // Test instrumentation: records the reorder buffer's peak size for the bound assertions.
    reorder_peak: &AtomicUsize,
    scan_span: &tracing::Span,
    // watch, not mpsc: a progress consumer wants the latest snapshot, never a backlog.
    progress: Option<&watch::Sender<DiscoveryProgress>>,
    // None = no checkpointing, zero overhead on the hot path.
    mut checkpoint: Option<CheckpointWriter>,
) -> Result<DiscoverySummary, RastreoError> {
    let prober_kinds: Vec<ProbeKind> = probers.iter().map(|p| p.kind()).collect();
    let sink_type = sink.kind();
    let capacity = scheduler.max_concurrent().max(1);
    let (tx, mut rx) = mpsc::channel::<TargetScan>(capacity);

    // Owned, not pinned: a `tokio::pin!` borrow would leave the future alive past the drop below.
    let mut scan = scheduler.run_scan(probers, targets, ctx, cancel.clone(), tx);

    let mut acc = ScanAccumulation::default();
    let mut best_key: Option<(usize, usize)> = None;
    let mut reorder: BTreeMap<usize, TargetScan> = BTreeMap::new();
    let mut next_expected: usize = 0;
    let mut buf: Vec<u8> = Vec::new();
    let mut records_emitted: usize = 0;
    let mut links_emitted: usize = 0;
    let mut profiles_emitted: usize = 0;
    let mut targets_completed: usize = 0;
    let mut emit_err: Option<RastreoError> = None;
    let mut scan_done = false;
    let mut assembler = TopologyAssembler::new(Arc::clone(scan_metadata));
    let mut profile_assembler = CollectionProfileAssembler::new(Arc::clone(scan_metadata));

    // Latest-wins send; a dropped receiver just means nobody is watching, so ignore the error.
    // `resume_base` shifts local completion counts to the global position, so a resumed run reports
    // K/N .. N rather than 0/(N-K).
    let publish = |completed: usize, records: usize, attempts: usize| {
        if let Some(tx) = progress {
            let _ = tx.send(DiscoveryProgress {
                targets_completed: resume_base + completed,
                targets_total: targets_resolved,
                records_emitted: records,
                probe_attempts: attempts,
                elapsed_ms: start.elapsed().as_millis(),
            });
        }
    };

    let stream_span = tracing::info_span!(parent: scan_span, "stream");

    // A `?` inside this block exits to the close below, never past it.
    let halted_err = async {
        loop {
            tokio::select! {
                // `biased` polls the scan branch first so its completion is observed before the channel
                // closes, latching `cancelled` at the same point the batch pipeline would.
                biased;
                _ = &mut scan, if !scan_done => {
                    acc.cancelled = *cancel.borrow();
                    scan_done = true;
                }
                maybe = rx.recv() => {
                    let Some(target_scan) = maybe else { break };
                    reorder.insert(target_scan.target_index, target_scan);
                    reorder_peak.fetch_max(reorder.len(), Ordering::Relaxed);
                    while let Some(ready) = reorder.remove(&next_expected) {
                        accumulate_target(&mut acc, &prober_kinds, &ready, &mut best_key);
                        // On an emit error, stop emitting but keep draining so remaining targets still
                        // probe and their metrics still accumulate — the summary metrics stay complete.
                        if emit_err.is_none() {
                            emit_target_records(
                                ready.outcomes,
                                fuser,
                                classifier,
                                encoder,
                                sink,
                                scan_metadata,
                                &mut assembler,
                                &mut profile_assembler,
                                &mut buf,
                                &mut records_emitted,
                                &mut emit_err,
                            )
                            .await?;
                        }
                        next_expected += 1;
                        targets_completed += 1;
                        publish(targets_completed, records_emitted, acc.probe_attempts);
                        // Flush-then-checkpoint at the cadence; a set emit_err froze the flushed prefix,
                        // so stop checkpointing and leave the last good checkpoint in place.
                        if emit_err.is_none() {
                            if let Some(writer) = checkpoint.as_mut() {
                                if let Err(e) = writer.maybe_checkpoint(sink, next_expected).await {
                                    emit_err = Some(e);
                                }
                            }
                        }
                    }
                }
            }
        }

        // A cancelled scan sends only fully-completed targets as a contiguous prefix, so the buffer is
        // normally empty here. Drain any straggler in ascending index order to match the batch order.
        for (_, ready) in std::mem::take(&mut reorder) {
            accumulate_target(&mut acc, &prober_kinds, &ready, &mut best_key);
            if emit_err.is_none() {
                emit_target_records(
                    ready.outcomes,
                    fuser,
                    classifier,
                    encoder,
                    sink,
                    scan_metadata,
                    &mut assembler,
                    &mut profile_assembler,
                    &mut buf,
                    &mut records_emitted,
                    &mut emit_err,
                )
                .await?;
            }
            targets_completed += 1;
            publish(targets_completed, records_emitted, acc.probe_attempts);
        }
        drop(stream_span);

        let finish_span = tracing::info_span!(
            parent: scan_span,
            "finish",
            records_emitted = tracing::field::Empty
        );
        let mut tail = fuser.finish()?;
        for record in &mut tail {
            classifier.classify(record)?;
            stamp_scan_metadata(record, scan_metadata);
            assembler.observe_record(record);
            profile_assembler.observe_record(record);
        }
        for record in &tail {
            if emit_err.is_some() {
                break;
            }
            buf.clear();
            if let Err(e) = encoder.encode_record(record, &mut buf) {
                emit_err = Some(e);
                break;
            }
            match write_encoded(sink, RecordKind::Device, &buf).await {
                Ok(written) => records_emitted += usize::from(written),
                Err(e) => {
                    emit_err = Some(e);
                    break;
                }
            }
        }
        finish_span.record("records_emitted", records_emitted as u64);
        drop(finish_span);

        // Second streams flush after every device record so the identity index is complete before correlation.
        for link in &assembler.finish() {
            if emit_err.is_some() {
                break;
            }
            buf.clear();
            if let Err(e) = encoder.encode_link(link, &mut buf) {
                emit_err = Some(e);
                break;
            }
            match write_encoded(sink, RecordKind::Link, &buf).await {
                Ok(written) => links_emitted += usize::from(written),
                Err(e) => {
                    emit_err = Some(e);
                    break;
                }
            }
        }

        for profile in &profile_assembler.finish() {
            if emit_err.is_some() {
                break;
            }
            buf.clear();
            if let Err(e) = encoder.encode_profile(profile, &mut buf) {
                emit_err = Some(e);
                break;
            }
            match write_encoded(sink, RecordKind::CollectionProfile, &buf).await {
                Ok(written) => profiles_emitted += usize::from(written),
                Err(e) => {
                    emit_err = Some(e);
                    break;
                }
            }
        }

        // Final snapshot: a buffering fuser (identity) emits its records in the finish block above, after the last drain-time publish.
        publish(targets_completed, records_emitted, acc.probe_attempts);
        Ok::<(), RastreoError>(())
    }
    .await
    .err();

    // Aborts probes still in flight: nothing reads their outcomes and a broker close can take seconds.
    drop(scan);

    // The guarantee stops here: a fallible call added between the block above and this line escapes it.
    let close_err = sink.close().await.err();

    if acc.cancelled {
        tracing::info!(records_emitted, "discovery cancelled; sink closed");
    }

    // Finalize on a clean drain only: a fuse or classify failure, a mid-scan sink error (emit or
    // flush), or a close failure leaves the last good checkpoint untouched. A completed scan deletes it
    // (nothing to resume); a cancelled scan records a final checkpoint over the full flushed prefix
    // that close() just made durable.
    let checkpoint_err = if halted_err.is_none() && emit_err.is_none() && close_err.is_none() {
        finalize_checkpoint(checkpoint.as_ref(), acc.cancelled, next_expected).err()
    } else {
        None
    };

    let dlq_records_by_type_and_class = sink.dlq_records_by_type_and_class();
    let dlq_records = dlq_records_by_type_and_class
        .iter()
        .fold(0u64, |sum, (_, _, c)| sum.saturating_add(*c)) as usize;
    let probes_by_kind = build_probes_by_kind(&acc.attempts_by_kind, &acc.errors_by_kind);

    // Ranked first: it halted record production, where a set emit_err only stopped emission mid-scan.
    if let Some(e) = halted_err {
        return Err(e);
    }
    if let Some(e) = emit_err {
        return Err(e);
    }
    if let Some(e) = close_err {
        return Err(e);
    }
    if let Some(e) = checkpoint_err {
        return Err(e);
    }

    Ok(DiscoverySummary {
        targets_resolved,
        probe_attempts: acc.probe_attempts,
        records_emitted,
        links_emitted,
        profiles_emitted,
        unresolvable_targets: Vec::new(),
        error_counts: acc.error_counts,
        probes_by_kind,
        dlq_records,
        dlq_records_by_type_and_class,
        sink_type: Some(sink_type),
        cancelled: acc.cancelled,
        first_probe_error: acc.first_probe_error,
        elapsed: start.elapsed(),
    })
}

/// Batch (buffer-then-emit) reference retained as the differential guard for [`stream_discovery`]:
/// drains the whole scan, accumulates metrics, then fuses and emits in one pass.
#[cfg(test)]
async fn collect_scans_sorted(
    scheduler: &BoundedScheduler,
    probers: Vec<Arc<dyn Prober>>,
    resolved: Vec<ResolvedTarget>,
    ctx: ProbeCtx,
    cancel: watch::Receiver<bool>,
) -> (Vec<TargetScan>, bool) {
    let capacity = scheduler.max_concurrent().max(1);
    let (tx, mut rx) = mpsc::channel::<TargetScan>(capacity);
    let scan = scheduler.run_scan(
        probers,
        Box::new(resolved.into_iter()),
        ctx,
        cancel.clone(),
        tx,
    );
    tokio::pin!(scan);
    let mut out = Vec::new();
    let mut cancelled = false;
    let mut done = false;
    loop {
        tokio::select! {
            biased;
            _ = &mut scan, if !done => { cancelled = *cancel.borrow(); done = true; }
            maybe = rx.recv() => {
                match maybe {
                    Some(s) => out.push(s),
                    None => break,
                }
            }
        }
    }
    out.sort_by_key(|s| s.target_index);
    (out, cancelled)
}

#[cfg(test)]
fn accumulate_scans(
    scans: Vec<TargetScan>,
    prober_kinds: &[ProbeKind],
    cancelled: bool,
) -> ScanAccumulation {
    let mut acc = ScanAccumulation {
        cancelled,
        ..Default::default()
    };
    let mut best_key: Option<(usize, usize)> = None;
    for scan in scans {
        accumulate_target(&mut acc, prober_kinds, &scan, &mut best_key);
        for (_, result) in scan.outcomes {
            if let Ok(outcome) = result {
                acc.all_outcomes.push(outcome);
            }
        }
    }
    acc
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn finish_discovery_ref(
    mut acc: ScanAccumulation,
    fuser: &mut dyn Fuser,
    classifier: &dyn Classifier,
    encoder: &dyn Encoder,
    sink: &mut dyn Sink,
    scan_metadata: &Arc<ScanMetadata>,
    targets_resolved: usize,
    start: Instant,
) -> Result<DiscoverySummary, RastreoError> {
    let sink_type = sink.kind();

    let mut assembler = TopologyAssembler::new(Arc::clone(scan_metadata));
    assembler.observe_outcomes(&acc.all_outcomes);
    let mut profile_assembler = CollectionProfileAssembler::new(Arc::clone(scan_metadata));
    profile_assembler.observe_outcomes(&acc.all_outcomes);
    let all_outcomes = std::mem::take(&mut acc.all_outcomes);

    let mut buf: Vec<u8> = Vec::new();
    let mut records_emitted: usize = 0;
    let mut links_emitted: usize = 0;
    let mut profiles_emitted: usize = 0;
    let mut emit_err: Option<RastreoError> = None;

    // A `?` inside this block exits to the close below, never past it.
    let halted_err = async {
        let mut records = crate::fuser::drive_fuser(fuser, all_outcomes)?;
        for record in &mut records {
            classifier.classify(record)?;
            stamp_scan_metadata(record, scan_metadata);
            assembler.observe_record(record);
            profile_assembler.observe_record(record);
        }

        for record in &records {
            buf.clear();
            if let Err(e) = encoder.encode_record(record, &mut buf) {
                emit_err = Some(e);
                break;
            }
            match write_encoded(sink, RecordKind::Device, &buf).await {
                Ok(written) => records_emitted += usize::from(written),
                Err(e) => {
                    emit_err = Some(e);
                    break;
                }
            }
        }

        for link in &assembler.finish() {
            if emit_err.is_some() {
                break;
            }
            buf.clear();
            if let Err(e) = encoder.encode_link(link, &mut buf) {
                emit_err = Some(e);
                break;
            }
            match write_encoded(sink, RecordKind::Link, &buf).await {
                Ok(written) => links_emitted += usize::from(written),
                Err(e) => {
                    emit_err = Some(e);
                    break;
                }
            }
        }

        for profile in &profile_assembler.finish() {
            if emit_err.is_some() {
                break;
            }
            buf.clear();
            if let Err(e) = encoder.encode_profile(profile, &mut buf) {
                emit_err = Some(e);
                break;
            }
            match write_encoded(sink, RecordKind::CollectionProfile, &buf).await {
                Ok(written) => profiles_emitted += usize::from(written),
                Err(e) => {
                    emit_err = Some(e);
                    break;
                }
            }
        }
        Ok::<(), RastreoError>(())
    }
    .await
    .err();

    let close_err = sink.close().await.err();

    let dlq_records_by_type_and_class = sink.dlq_records_by_type_and_class();
    let dlq_records = dlq_records_by_type_and_class
        .iter()
        .fold(0u64, |sum, (_, _, c)| sum.saturating_add(*c)) as usize;
    let probes_by_kind = build_probes_by_kind(&acc.attempts_by_kind, &acc.errors_by_kind);

    if let Some(e) = halted_err {
        return Err(e);
    }
    if let Some(e) = emit_err {
        return Err(e);
    }
    if let Some(e) = close_err {
        return Err(e);
    }

    Ok(DiscoverySummary {
        targets_resolved,
        probe_attempts: acc.probe_attempts,
        records_emitted,
        links_emitted,
        profiles_emitted,
        unresolvable_targets: Vec::new(),
        error_counts: acc.error_counts,
        probes_by_kind,
        dlq_records,
        dlq_records_by_type_and_class,
        sink_type: Some(sink_type),
        cancelled: acc.cancelled,
        first_probe_error: acc.first_probe_error,
        elapsed: start.elapsed(),
    })
}

fn stamp_scan_metadata(record: &mut DeviceRecord, scan_metadata: &Arc<ScanMetadata>) {
    record.scan_metadata = Arc::clone(scan_metadata);
}

fn finalize_checkpoint(
    writer: Option<&CheckpointWriter>,
    cancelled: bool,
    next_expected: usize,
) -> Result<(), RastreoError> {
    let Some(writer) = writer else {
        return Ok(());
    };
    if cancelled {
        // next_expected == 0: no target finished this run. Leave the path as-is — for a fresh scan
        // that means empty, for a resume the existing checkpoint still records the prior prefix.
        if next_expected > 0 {
            writer.write_at(writer.record_index(next_expected))?;
        }
    } else {
        writer.delete()?;
    }
    Ok(())
}

fn build_probes_by_kind(
    attempts: &[usize; PROBE_KIND_COUNT],
    errors: &[usize; PROBE_KIND_COUNT],
) -> Vec<ProbeKindSummary> {
    let mut out = Vec::new();
    for kind in ProbeKind::all() {
        let idx = kind.index();
        if attempts[idx] == 0 && errors[idx] == 0 {
            continue;
        }
        out.push(ProbeKindSummary {
            kind: *kind,
            attempted: attempts[idx],
            errored: errors[idx],
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::classifier::{ClassifierConfig, MergeMode};
    use crate::config::BaseProbeConfig;
    use crate::encoder::EncoderConfig;
    use crate::error::ConfigError;
    use crate::fuser::FuserConfig;
    use crate::model::Target;
    use crate::prober::ProberConfig;

    fn scenario_with_probers(probers: Vec<ProberConfig>) -> DiscoverScenarioConfig {
        DiscoverScenarioConfig {
            base: BaseProbeConfig::default(),
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers,
        }
    }

    #[tokio::test]
    async fn run_discovery_rejects_retired_rate_limit_field() {
        use crate::config::{ScenarioEntry, ScenarioFile};

        // The server POST /scans path bypasses parse_scenario_file, so the pipeline must reject.
        let json = r#"{
            "version": 1,
            "kind": "discovery",
            "scenarios": [
                {
                    "signal_type": "discover",
                    "rate_limit": 50,
                    "targets": [{"Ip": "127.0.0.1"}],
                    "probers": [{"type": "tcp_connect", "ports": [22]}]
                }
            ]
        }"#;
        let file: ScenarioFile = serde_json::from_str(json).expect("deserialize");
        let ScenarioEntry::Discover(scenario) = &file.scenarios[0];

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let err = run_discovery(
            RunOptions::new(scenario)
                .resolver(resolver)
                .sink(Box::new(mem)),
        )
        .await
        .expect_err("retired rate_limit must error");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("max_concurrent"), "msg: {msg}");
                assert!(msg.contains("probe_rate"), "msg: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_discovery_empty_probers_returns_config_error() {
        let scenario = scenario_with_probers(Vec::new());
        let err = run_discovery(RunOptions::new(&scenario))
            .await
            .expect_err("empty probers");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("probers"), "unexpected message: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_discovery_empty_targets_returns_config_error() {
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig::default(),
            targets: Vec::new(),
            probers: vec![ProberConfig::TcpConnect { ports: vec![22] }],
        };
        let err = run_discovery(RunOptions::new(&scenario))
            .await
            .expect_err("empty targets");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("targets"), "unexpected message: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_invalid_fuser_knob_is_refused_before_the_sink_touches_its_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("records.ndjson");
        let base = BaseProbeConfig {
            sink: Some(SinkConfig::File { path: path.clone() }),
            fuser: Some(FuserConfig::Direct {
                include_unreachable: None,
                confidence_baseline: Some(5.0),
                confidence_per_signal: None,
            }),
            timeout_ms: Some(500),
            ..Default::default()
        };
        let scenario = DiscoverScenarioConfig {
            base,
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![22] }],
        };

        let err = run_discovery(RunOptions::new(&scenario))
            .await
            .expect_err("a confidence_baseline above 1.0 is invalid");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("confidence_baseline"), "msg: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
        assert!(
            !path.exists(),
            "a config the pipeline can reject offline must not reach the sink"
        );
    }

    #[tokio::test]
    async fn run_discovery_emits_record_for_open_loopback_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("records.ndjson");

        let base = BaseProbeConfig {
            sink: Some(SinkConfig::File { path: path.clone() }),
            timeout_ms: Some(500),
            ..Default::default()
        };

        let scenario = DiscoverScenarioConfig {
            base,
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let summary = run_discovery(RunOptions::new(&scenario))
            .await
            .expect("run_discovery");
        assert_eq!(summary.targets_resolved, 1);
        assert_eq!(summary.probe_attempts, 1);
        assert!(summary.error_counts.is_empty());
        assert_eq!(summary.records_emitted, 1);

        let bytes = std::fs::read(&path).expect("read");
        let lines: Vec<&[u8]> = bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(lines.len(), 1);
        let record: crate::model::DeviceRecord =
            serde_json::from_slice(lines[0]).expect("parse json");
        assert_eq!(record.mgmt_ip, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(record
            .signals
            .iter()
            .any(|s| matches!(s, crate::model::Signal::OpenPort(p) if *p == port)));
    }

    #[tokio::test]
    async fn run_discovery_unreachable_target_emits_no_records() {
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let closed_port = closed_listener.local_addr().expect("local_addr").port();
        drop(closed_listener);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("none.ndjson");

        let base = BaseProbeConfig {
            sink: Some(SinkConfig::File { path: path.clone() }),
            timeout_ms: Some(200),
            ..Default::default()
        };

        let scenario = DiscoverScenarioConfig {
            base,
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect {
                ports: vec![closed_port],
            }],
        };

        let summary = run_discovery(RunOptions::new(&scenario))
            .await
            .expect("run_discovery");
        assert_eq!(summary.targets_resolved, 1);
        assert_eq!(summary.probe_attempts, 1);
        assert_eq!(summary.records_emitted, 0);

        let bytes = std::fs::read(&path).expect("read");
        assert!(bytes.is_empty(), "no records expected, got {bytes:?}");
    }

    #[tokio::test]
    async fn run_discovery_uses_provided_resolver() {
        use crate::model::ResolvedTarget;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingResolver {
            inner: HickoryResolver,
            calls: AtomicUsize,
        }

        #[async_trait::async_trait]
        impl Resolver for CountingResolver {
            async fn resolve(
                &self,
                target: &crate::model::Target,
            ) -> Result<Vec<ResolvedTarget>, RastreoError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.inner.resolve(target).await
            }
        }

        let resolver = Arc::new(CountingResolver {
            inner: HickoryResolver::from_system().expect("init"),
            calls: AtomicUsize::new(0),
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let resolver_dyn: Arc<dyn Resolver> = resolver.clone();
        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let sink: Box<dyn Sink> = Box::new(mem);
        let _summary = run_discovery(RunOptions::new(&scenario).resolver(resolver_dyn).sink(sink))
            .await
            .expect("run_discovery");

        assert!(resolver.calls.load(Ordering::SeqCst) >= 1);
        assert!(!handle.bytes().is_empty());
    }

    #[tokio::test]
    async fn run_discovery_uses_provided_sink() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem)),
        )
        .await
        .expect("run_discovery");
        assert_eq!(summary.records_emitted, 1);
        let lines = handle.ndjson_lines();
        assert_eq!(lines.len(), 1);
        let record: crate::model::DeviceRecord =
            serde_json::from_str(&lines[0]).expect("parse json");
        assert_eq!(record.mgmt_ip, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn discovery_summary_serializes_elapsed_as_millis_field() {
        let summary = DiscoverySummary {
            targets_resolved: 1,
            probe_attempts: 2,
            records_emitted: 1,
            elapsed: Duration::from_millis(142),
            ..Default::default()
        };
        let json: serde_json::Value = serde_json::to_value(&summary).expect("serialize");
        assert_eq!(json["elapsed_ms"], 142);
        assert_eq!(json["records_emitted"], 1);
        assert!(json.get("elapsed").is_none());
    }

    #[test]
    fn discovery_summary_serializes_cancelled_field() {
        let summary = DiscoverySummary {
            targets_resolved: 1,
            probe_attempts: 2,
            records_emitted: 1,
            cancelled: true,
            elapsed: Duration::from_millis(7),
            ..Default::default()
        };
        let json: serde_json::Value = serde_json::to_value(&summary).expect("serialize");
        assert_eq!(json["cancelled"], true);
    }

    #[tokio::test]
    async fn run_discovery_populates_probes_by_kind_and_sink_type() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        Box::leak(Box::new(listener));

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem)),
        )
        .await
        .expect("run_discovery");
        assert_eq!(summary.sink_type, Some(crate::sink::SinkType::Memory));
        assert_eq!(summary.dlq_records, 0);
        assert_eq!(summary.probes_by_kind.len(), 1);
        assert_eq!(summary.probes_by_kind[0].kind, ProbeKind::TcpConnect);
        assert_eq!(summary.probes_by_kind[0].attempted, 1);
        assert_eq!(summary.probes_by_kind[0].errored, 0);
    }

    #[test]
    fn discovery_summary_default_has_none_sink_type_and_empty_kind_breakdown() {
        let summary = DiscoverySummary::default();
        assert_eq!(summary.probes_by_kind.len(), 0);
        assert_eq!(summary.dlq_records, 0);
        assert!(summary.dlq_records_by_type_and_class.is_empty());
        assert!(summary.sink_type.is_none());
        assert!(summary.first_probe_error.is_none());
        assert!(summary.error_counts.is_empty());
    }

    #[test]
    fn discovery_summary_omits_first_probe_error_and_error_counts_from_wire_when_empty() {
        let summary = DiscoverySummary::default();
        let json: serde_json::Value = serde_json::to_value(&summary).expect("serialize");
        assert!(
            json.get("first_probe_error").is_none(),
            "first_probe_error must be skipped when None: {json}"
        );
        assert!(
            json.get("error_counts").is_none(),
            "error_counts must be skipped when empty: {json}"
        );
    }

    #[test]
    fn discovery_summary_serializes_first_probe_error_and_error_counts_when_present() {
        let mut error_counts = BTreeMap::new();
        error_counts.insert(ProbeErrorKind::DecodeFailed, 3);
        let summary = DiscoverySummary {
            first_probe_error: Some(ProbeFault::new(
                ProbeErrorKind::PermissionDenied,
                "permission denied",
            )),
            error_counts,
            ..Default::default()
        };
        let json: serde_json::Value = serde_json::to_value(&summary).expect("serialize");
        assert_eq!(json["first_probe_error"]["kind"], "permission_denied");
        assert_eq!(json["first_probe_error"]["detail"], "permission denied");
        assert_eq!(json["error_counts"]["decode_failed"], 3);
    }

    #[tokio::test]
    async fn run_discovery_reports_no_probe_errors_for_dark_targets() {
        use crate::prober::UdpProtocol;

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(100),
                ..Default::default()
            },
            targets: vec![
                Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            ],
            probers: vec![ProberConfig::Udp {
                ports: vec![1],
                protocol: UdpProtocol::Ntp,
            }],
        };

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem)),
        )
        .await
        .expect("returns summary");

        assert_eq!(summary.probe_attempts, 2);
        assert!(
            summary.error_counts.is_empty(),
            "a target that does not answer is a discovery result, not a probe error"
        );
        assert!(summary.first_probe_error.is_none());
        assert_eq!(summary.records_emitted, 0);
        let udp = summary
            .probes_by_kind
            .iter()
            .find(|k| k.kind == ProbeKind::Udp)
            .expect("udp kind summary");
        assert_eq!(udp.attempted, 2);
        assert_eq!(udp.errored, 0);
    }

    #[cfg(feature = "snmp")]
    async fn spawn_undecodable_snmp_agent() -> u16 {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind agent");
        let port = socket.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                if let Ok((_, peer)) = socket.recv_from(&mut buf).await {
                    let _ = socket.send_to(&[0xff, 0xfe, 0xfd, 0xfc], peer).await;
                }
            }
        });
        port
    }

    #[cfg(feature = "snmp")]
    #[tokio::test]
    async fn run_discovery_snmp_decode_failure_keeps_the_device_and_counts_the_fault() {
        use crate::prober::snmp::{SnmpVersion, UsmCredentials};

        let port = spawn_undecodable_snmp_agent().await;
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::Snmp {
                ports: vec![port],
                version: SnmpVersion::V2c,
                community: crate::prober::Community("public".into()),
                credentials: UsmCredentials::default(),
            }],
        };

        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem)),
        )
        .await
        .expect("returns summary");

        assert_eq!(
            summary.records_emitted, 1,
            "the agent answered on the port; the decode-failed device is kept, not dropped"
        );
        assert_eq!(
            summary
                .error_counts
                .get(&ProbeErrorKind::DecodeFailed)
                .copied(),
            Some(1),
            "the decode failure is tallied as a fault: {:?}",
            summary.error_counts
        );
        let record: crate::model::DeviceRecord =
            serde_json::from_str(&handle.ndjson_lines()[0]).expect("parse record");
        assert!(
            record.probe_kinds.contains(&ProbeKind::Snmp),
            "the probe got a response, so Snmp is provenance: {:?}",
            record.probe_kinds
        );
    }

    #[cfg(feature = "snmp")]
    #[tokio::test]
    async fn run_discovery_latches_the_first_fault_and_ignores_subsequent() {
        use crate::prober::snmp::{SnmpVersion, UsmCredentials};

        let snmp_prober_on = |port: u16| ProberConfig::Snmp {
            ports: vec![port],
            version: SnmpVersion::V2c,
            community: crate::prober::Community("public".into()),
            credentials: UsmCredentials::default(),
        };
        let first_port = spawn_undecodable_snmp_agent().await;
        let second_port = spawn_undecodable_snmp_agent().await;

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![snmp_prober_on(first_port), snmp_prober_on(second_port)],
        };

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem)),
        )
        .await
        .expect("returns summary");

        assert_eq!(
            summary
                .error_counts
                .get(&ProbeErrorKind::DecodeFailed)
                .copied(),
            Some(2),
            "an undecodable agent reply is a probe fault, not an absent host"
        );
        let fault = summary
            .first_probe_error
            .as_ref()
            .expect("first probe error must be latched");
        assert_eq!(fault.kind, ProbeErrorKind::DecodeFailed);
        assert!(
            fault.detail.contains("decode"),
            "must carry the fault, got: {}",
            fault.detail
        );
        assert!(
            fault.detail.contains(&first_port.to_string()),
            "the first fault must win the latch, got: {}",
            fault.detail
        );
        assert!(
            !fault.detail.contains(&second_port.to_string()),
            "a later fault must not overwrite the latched first one, got: {}",
            fault.detail
        );
    }

    #[tokio::test]
    async fn include_unreachable_emits_a_record_per_dark_target() {
        use crate::prober::UdpProtocol;

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(100),
                fuser: Some(FuserConfig::Direct {
                    include_unreachable: Some(true),
                    confidence_baseline: None,
                    confidence_per_signal: None,
                }),
                ..Default::default()
            },
            targets: vec![
                Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            ],
            probers: vec![ProberConfig::Udp {
                ports: vec![1],
                protocol: UdpProtocol::Ntp,
            }],
        };

        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem)),
        )
        .await
        .expect("returns summary");

        assert!(summary.error_counts.is_empty());
        assert_eq!(
            summary.records_emitted, 2,
            "a dark host is an outcome, so include_unreachable emits one record per dark IP"
        );
        let records: Vec<crate::model::DeviceRecord> = handle
            .ndjson_lines()
            .iter()
            .map(|l| serde_json::from_str(l).expect("parse record"))
            .collect();
        for record in &records {
            assert!(
                record.probe_kinds.is_empty(),
                "nothing responded, so nothing is provenance: {:?}",
                record.probe_kinds
            );
            assert!(record.signals.is_empty());
        }
    }

    #[tokio::test]
    async fn probe_kinds_on_a_reachable_record_exclude_silent_probers() {
        use crate::prober::UdpProtocol;

        let open_port = open_loopback_port().await;
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(100),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![
                ProberConfig::TcpConnect {
                    ports: vec![open_port],
                },
                ProberConfig::Udp {
                    ports: vec![1],
                    protocol: UdpProtocol::Ntp,
                },
            ],
        };

        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem)),
        )
        .await
        .expect("returns summary");

        assert_eq!(summary.records_emitted, 1);
        let lines = handle.ndjson_lines();
        let record: crate::model::DeviceRecord =
            serde_json::from_str(&lines[0]).expect("parse record");
        assert_eq!(
            record.probe_kinds,
            vec![ProbeKind::TcpConnect],
            "the silent udp prober answered nothing and must not claim provenance"
        );
    }

    #[tokio::test]
    async fn run_discovery_first_probe_error_is_none_when_no_errors() {
        let port = open_loopback_port().await;
        let scenario = scenario_for_port(port);
        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem)),
        )
        .await
        .expect("run_discovery");
        assert_eq!(summary.records_emitted, 1);
        assert!(
            summary.first_probe_error.is_none(),
            "first_probe_error must stay None when no probe errors: {:?}",
            summary.first_probe_error
        );
    }

    #[tokio::test]
    async fn discovery_summary_populates_dlq_records_by_type_and_class_on_tee_wrapped_kafka() {
        use crate::sink::{TeeChild, TeeSink, SINK_ERROR_CLASS_COUNT};

        struct KafkaLikeSink {
            dlq: u64,
        }

        #[async_trait::async_trait]
        impl crate::sink::Sink for KafkaLikeSink {
            async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
                self.dlq += 1;
                Ok(())
            }
            async fn flush(&mut self) -> Result<(), RastreoError> {
                Ok(())
            }
            fn last_write_delivered(&self) -> bool {
                true
            }
            fn kind(&self) -> SinkType {
                SinkType::Kafka
            }
            fn dlq_records_by_class(&self) -> [u64; SINK_ERROR_CLASS_COUNT] {
                let mut out = [0; SINK_ERROR_CLASS_COUNT];
                out[SinkErrorClass::ProduceFailure.index()] = self.dlq;
                out
            }
        }

        let port = open_loopback_port().await;
        let scenario = scenario_for_port(port);

        let mem = crate::sink::MemorySink::new();
        let kafka = KafkaLikeSink { dlq: 0 };
        let tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(mem)),
            TeeChild::Owned(Box::new(kafka)),
        ]);
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(tee)),
        )
        .await
        .expect("run_discovery");

        assert_eq!(summary.sink_type, Some(SinkType::Tee));
        assert_eq!(summary.records_emitted, 1);
        assert_eq!(summary.dlq_records, 1);
        assert_eq!(
            summary.dlq_records_by_type_and_class,
            vec![(SinkType::Kafka, SinkErrorClass::ProduceFailure, 1)]
        );
    }

    #[tokio::test]
    async fn run_discovery_applies_default_concurrency_and_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("defaults.ndjson");

        let base = BaseProbeConfig {
            sink: Some(SinkConfig::File { path }),
            ..Default::default()
        };

        let scenario = DiscoverScenarioConfig {
            base,
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let summary = run_discovery(RunOptions::new(&scenario))
            .await
            .expect("run_discovery");
        assert_eq!(summary.records_emitted, 1);
    }

    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct FailingSinkInner {
        writes: AtomicUsize,
        flushes: AtomicUsize,
    }

    struct FailingSink {
        inner: Arc<FailingSinkInner>,
        fail_after_writes: usize,
    }

    impl FailingSink {
        fn new(fail_after_writes: usize) -> Self {
            Self {
                inner: Arc::new(FailingSinkInner::default()),
                fail_after_writes,
            }
        }

        fn handle(&self) -> FailingSinkHandle {
            FailingSinkHandle {
                inner: Arc::clone(&self.inner),
            }
        }
    }

    #[derive(Clone)]
    struct FailingSinkHandle {
        inner: Arc<FailingSinkInner>,
    }

    impl FailingSinkHandle {
        fn writes(&self) -> usize {
            self.inner.writes.load(Ordering::SeqCst)
        }
        fn flushes(&self) -> usize {
            self.inner.flushes.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl crate::sink::Sink for FailingSink {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            let n = self.inner.writes.fetch_add(1, Ordering::SeqCst) + 1;
            if n > self.fail_after_writes {
                return Err(RastreoError::Sink(crate::sink::SinkError::new(
                    SinkErrorClass::WriteFailure,
                    std::io::Error::other("simulated write failure"),
                )));
            }
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            self.inner.flushes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn last_write_delivered(&self) -> bool {
            true
        }
        fn kind(&self) -> SinkType {
            SinkType::Memory
        }
    }

    async fn open_loopback_port() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        Box::leak(Box::new(listener));
        port
    }

    fn scenario_for_port(port: u16) -> DiscoverScenarioConfig {
        DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        }
    }

    #[tokio::test]
    async fn targets_resolved_equals_the_streamed_target_count_across_specs() {
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(100),
                ..Default::default()
            },
            targets: vec![
                Target::Cidr("127.0.0.0/30".parse().expect("cidr")),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5))),
            ],
            probers: vec![ProberConfig::TcpConnect { ports: vec![1] }],
        };

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem)),
        )
        .await
        .expect("run_discovery");
        assert_eq!(
            summary.targets_resolved, 3,
            "the /30 (2 hosts) plus one IP stream 3 targets"
        );
        assert_eq!(
            summary.probe_attempts, 3,
            "the pre-flight denominator equals the number of targets the stream yielded"
        );
    }

    #[tokio::test]
    async fn overlapping_specs_emit_one_record_per_duplicate_target() {
        let port = open_loopback_port().await;
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![
                Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem)),
        )
        .await
        .expect("run_discovery");

        assert_eq!(
            summary.targets_resolved, 2,
            "no cross-target dedup: the overlapping spec is counted twice"
        );
        assert_eq!(summary.probe_attempts, 2);
        assert_eq!(
            summary.records_emitted, 2,
            "the overlapped IP emits one record per occurrence"
        );
        assert_eq!(handle.ndjson_lines().len(), 2);
    }

    #[tokio::test]
    async fn over_cap_scenario_is_rejected_before_any_probe() {
        let inner: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let guard: Arc<dyn Resolver> =
            Arc::new(crate::resolver::GuardedResolver::new(inner, None, Some(1)));
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(100),
                ..Default::default()
            },
            targets: vec![Target::Cidr("10.0.0.0/30".parse().expect("cidr"))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![22] }],
        };

        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let err = run_discovery(
            RunOptions::new(&scenario)
                .resolver(guard)
                .sink(Box::new(mem)),
        )
        .await
        .expect_err("the aggregate cap must reject the scan");
        assert!(matches!(
            err,
            RastreoError::Resolver(crate::error::ResolverError::AggregateHostCapExceeded { .. })
        ));
        assert!(
            handle.bytes().is_empty(),
            "rejection is pre-flight: no probe ran and no record was emitted"
        );
    }

    #[tokio::test]
    async fn out_of_allowlist_scenario_is_rejected_before_any_probe() {
        let inner: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let guard: Arc<dyn Resolver> = Arc::new(crate::resolver::GuardedResolver::new(
            inner,
            Some(vec!["10.0.0.0/8".parse().expect("net")]),
            None,
        ));
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(100),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![22] }],
        };

        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let err = run_discovery(
            RunOptions::new(&scenario)
                .resolver(guard)
                .sink(Box::new(mem)),
        )
        .await
        .expect_err("an out-of-allow-list target must reject the scan");
        assert!(matches!(
            err,
            RastreoError::Resolver(crate::error::ResolverError::TargetNotAllowed { .. })
        ));
        assert!(
            handle.bytes().is_empty(),
            "rejection is pre-flight: no probe ran and no record was emitted"
        );
    }

    #[tokio::test]
    async fn run_discovery_flushes_sink_even_after_emit_error() {
        let port = open_loopback_port().await;
        let scenario = scenario_for_port(port);

        let sink = Box::new(FailingSink::new(0));
        let handle = sink.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let (_tx, rx) = watch::channel(false);

        let err = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(sink)
                .cancel(rx),
        )
        .await
        .expect_err("write must error");
        match &err {
            RastreoError::Sink(e) => {
                assert!(
                    e.source.to_string().contains("simulated"),
                    "unexpected msg: {}",
                    e.source
                );
                assert_eq!(e.class, SinkErrorClass::WriteFailure);
            }
            other => panic!("expected Sink error, got {other:?}"),
        }
        assert_eq!(
            err.sink_error_class(),
            Some(SinkErrorClass::WriteFailure),
            "the pipeline surfaces the failing sink's carried class"
        );
        assert!(handle.writes() >= 1, "write must have been attempted");
        assert_eq!(handle.flushes(), 1, "flush must be called after error");
    }

    #[tokio::test]
    async fn run_discovery_flushes_sink_on_cancellation_before_any_emit() {
        let port = open_loopback_port().await;
        let scenario = scenario_for_port(port);

        let (tx, rx) = watch::channel(false);
        tx.send(true).expect("send cancel");

        let mem = crate::sink::MemorySink::new();
        let mem_handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));

        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem))
                .cancel(rx),
        )
        .await
        .expect("cancellation path returns Ok summary");
        assert!(summary.cancelled, "cancelled flag must be set");
        assert_eq!(summary.records_emitted, 0);
        assert_eq!(summary.probe_attempts, 0);
        assert!(
            mem_handle.bytes().is_empty(),
            "no records emitted, sink empty"
        );
    }

    #[tokio::test]
    async fn run_discovery_cancellation_returns_partial_summary_with_cancelled_true() {
        let port = open_loopback_port().await;
        let mut scenario = scenario_for_port(port);
        scenario.probers = vec![
            ProberConfig::TcpConnect { ports: vec![port] },
            ProberConfig::TcpConnect { ports: vec![port] },
        ];

        let (tx, rx) = watch::channel(false);
        tx.send(true).expect("send cancel");

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem))
                .cancel(rx),
        )
        .await
        .expect("cancellation returns summary");
        assert!(summary.cancelled);
        assert_eq!(summary.probe_attempts, 0);
        assert!(summary.error_counts.is_empty());
        assert_eq!(summary.records_emitted, 0);
    }

    #[tokio::test]
    async fn run_discovery_cancel_emits_completed_targets_atomically() {
        let port = open_loopback_port().await;

        // 198.51.100.x is TEST-NET-2: connects there time out, so the scan is still priming new
        // targets when the 50ms cancel lands. Loopback target 0 finishes fast and reaches the sink.
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(400),
                max_concurrent: Some(4),
                ..Default::default()
            },
            targets: vec![
                Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3))),
            ],
            probers: vec![
                ProberConfig::TcpConnect { ports: vec![port] },
                ProberConfig::TcpConnect { ports: vec![port] },
            ],
        };

        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = tx.send(true);
        });

        let mem = crate::sink::MemorySink::new();
        let mem_handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem))
                .cancel(rx),
        )
        .await
        .expect("returns summary");

        assert!(summary.cancelled, "cancelled flag must be true");
        assert_eq!(
            summary.probe_attempts % 2,
            0,
            "target-outer cancellation is atomic per target: a returned target carries every prober's outcome, so attempts is a multiple of the prober count"
        );
        assert!(
            summary.records_emitted >= 1,
            "the completed loopback target's record must reach the sink even though the run was cancelled"
        );
        assert!(
            !mem_handle.ndjson_lines().is_empty(),
            "sink received at least one NDJSON line from a completed target"
        );
    }

    struct CancelAfterFirstWriteSink {
        cancel_tx: watch::Sender<bool>,
        delegate: crate::sink::MemorySink,
        first: bool,
        flushes: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl crate::sink::Sink for CancelAfterFirstWriteSink {
        async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
            self.delegate.write(data).await?;
            if self.first {
                self.first = false;
                let _ = self.cancel_tx.send(true);
            }
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            self.flushes.fetch_add(1, Ordering::SeqCst);
            self.delegate.flush().await
        }
        fn last_write_delivered(&self) -> bool {
            self.delegate.last_write_delivered()
        }
        fn kind(&self) -> SinkType {
            SinkType::Memory
        }
    }

    #[tokio::test]
    async fn run_discovery_cancel_signaled_mid_emit_drains_all_records() {
        let port = open_loopback_port().await;

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let (tx, rx) = watch::channel(false);
        let mem = crate::sink::MemorySink::new();
        let mem_handle = mem.handle();
        let flushes = Arc::new(AtomicUsize::new(0));
        let sink = Box::new(CancelAfterFirstWriteSink {
            cancel_tx: tx,
            delegate: mem,
            first: true,
            flushes: Arc::clone(&flushes),
        });
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(sink)
                .cancel(rx),
        )
        .await
        .expect("cancel mid-emit returns summary");

        assert_eq!(
            summary.records_emitted, 1,
            "the sole record must reach the sink; emit loop must not short-circuit on cancel"
        );
        assert!(
            !summary.cancelled,
            "cancel arrived after the prober loop and post-loop re-check; cancelled stays false"
        );
        assert_eq!(mem_handle.ndjson_lines().len(), 1);
        assert!(
            flushes.load(Ordering::SeqCst) >= 1,
            "flush must be called on every exit path"
        );
    }

    #[tokio::test]
    async fn run_discovery_cancel_during_single_prober_run_sets_cancelled_flag() {
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(200),
                max_concurrent: Some(4),
                // pace starts so scheduler.run outlasts the 50ms cancel — deterministic, not connect-timing dependent
                probe_rate: Some(10),
                ..Default::default()
            },
            targets: vec![
                Target::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3))),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4))),
            ],
            probers: vec![ProberConfig::TcpConnect { ports: vec![1] }],
        };

        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = tx.send(true);
        });

        let sink = Box::new(FailingSink::new(usize::MAX));
        let handle = sink.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(sink)
                .cancel(rx),
        )
        .await
        .expect("returns summary");

        assert!(
            summary.cancelled,
            "post-loop re-check must observe cancel signaled during the single in-flight scheduler.run"
        );
        assert_eq!(
            summary.probe_attempts, 4,
            "scheduler.run completes naturally; all targets attempted"
        );
        assert_eq!(
            summary.records_emitted, 0,
            "all targets unreachable; no records to emit"
        );
        assert_eq!(handle.flushes(), 1, "flush must run on the cancel path");
    }

    #[tokio::test]
    async fn run_discovery_non_cancelled_path_sets_cancelled_false() {
        let port = open_loopback_port().await;
        let scenario = scenario_for_port(port);

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem)),
        )
        .await
        .expect("run_discovery");
        assert!(!summary.cancelled);
        assert_eq!(summary.records_emitted, 1);
    }

    fn two_loopback_targets(port: u16) -> DiscoverScenarioConfig {
        DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                max_concurrent: Some(1),
                ..Default::default()
            },
            targets: vec![
                Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            ],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        }
    }

    #[tokio::test]
    async fn progress_reaches_total_and_advances_monotonically() {
        let port = open_loopback_port().await;
        let scenario = two_loopback_targets(port);

        let (tx, rx) = watch::channel(DiscoveryProgress::default());
        let capture = tokio::spawn(async move {
            let mut rx = rx;
            let mut seq: Vec<DiscoveryProgress> = Vec::new();
            while rx.changed().await.is_ok() {
                seq.push(rx.borrow().clone());
            }
            seq
        });

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem))
                .progress(tx),
        )
        .await
        .expect("progress run returns summary");

        let seq = capture.await.expect("capture task joins");
        assert!(
            !seq.is_empty(),
            "at least the final snapshot must be captured"
        );
        for pair in seq.windows(2) {
            assert!(
                pair[1].targets_completed >= pair[0].targets_completed,
                "targets_completed must never go backwards: {pair:?}"
            );
        }
        let last = seq.last().expect("non-empty");
        assert_eq!(last.targets_total, summary.targets_resolved);
        assert_eq!(
            last.targets_completed, last.targets_total,
            "a completed scan drains every target: {last:?}"
        );
        assert_eq!(last.targets_total, 2);
    }

    #[tokio::test]
    async fn progress_hook_does_not_alter_the_summary() {
        let port = open_loopback_port().await;
        let scenario = two_loopback_targets(port);

        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let without = run_discovery(
            RunOptions::new(&scenario)
                .resolver(Arc::clone(&resolver))
                .sink(Box::new(crate::sink::MemorySink::new())),
        )
        .await
        .expect("no-progress run");

        let (tx, _rx) = watch::channel(DiscoveryProgress::default());
        let with = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(crate::sink::MemorySink::new()))
                .progress(tx),
        )
        .await
        .expect("progress run");

        assert_eq!(without.targets_resolved, with.targets_resolved);
        assert_eq!(without.probe_attempts, with.probe_attempts);
        assert_eq!(without.records_emitted, with.records_emitted);
        assert_eq!(without.cancelled, with.cancelled);
    }

    #[tokio::test]
    async fn progress_with_dropped_receiver_still_completes() {
        let port = open_loopback_port().await;
        let scenario = two_loopback_targets(port);

        let (tx, rx) = watch::channel(DiscoveryProgress::default());
        drop(rx);

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem))
                .progress(tx),
        )
        .await
        .expect("a dropped progress receiver must not fail the scan");
        assert_eq!(summary.targets_resolved, 2);
        // Only 127.0.0.1 holds the open port; 127.0.0.2 is refused, so exactly one record.
        assert_eq!(summary.records_emitted, 1);
    }

    #[tokio::test]
    async fn identity_final_snapshot_carries_finish_block_records() {
        let port = open_loopback_port().await;
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                max_concurrent: Some(1),
                fuser: Some(FuserConfig::Identity {
                    identity_hints: crate::fuser::IdentityHints::default(),
                    inner: Box::new(FuserConfig::Direct {
                        include_unreachable: None,
                        confidence_baseline: None,
                        confidence_per_signal: None,
                    }),
                }),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let (tx, rx) = watch::channel(DiscoveryProgress::default());
        let capture = tokio::spawn(async move {
            let mut rx = rx;
            let mut seq: Vec<DiscoveryProgress> = Vec::new();
            while rx.changed().await.is_ok() {
                seq.push(rx.borrow().clone());
            }
            seq
        });

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem))
                .progress(tx),
        )
        .await
        .expect("identity progress run returns summary");

        let seq = capture.await.expect("capture task joins");
        let last = seq.last().expect("at least the final snapshot is captured");
        assert!(
            summary.records_emitted > 0,
            "the identity scan emits a record for the reachable target: {summary:?}"
        );
        assert_eq!(
            last.records_emitted, summary.records_emitted,
            "the final snapshot must carry the identity fuser's finish-block records: {last:?}"
        );
    }

    #[derive(Default)]
    struct BatchingSinkInner {
        committed: std::sync::Mutex<Vec<Vec<u8>>>,
        closes: AtomicUsize,
        flushes: AtomicUsize,
    }

    struct BatchingSink {
        inner: Arc<BatchingSinkInner>,
        buffer: Vec<Vec<u8>>,
    }

    impl BatchingSink {
        fn new() -> Self {
            Self {
                inner: Arc::new(BatchingSinkInner::default()),
                buffer: Vec::new(),
            }
        }
        fn handle(&self) -> Arc<BatchingSinkInner> {
            Arc::clone(&self.inner)
        }
        fn commit(&mut self) {
            let mut committed = self
                .inner
                .committed
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            committed.extend(self.buffer.drain(..));
        }
    }

    #[async_trait::async_trait]
    impl crate::sink::Sink for BatchingSink {
        async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
            self.buffer.push(data.to_vec());
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            self.inner.flushes.fetch_add(1, Ordering::SeqCst);
            self.commit();
            Ok(())
        }
        async fn close(&mut self) -> Result<(), RastreoError> {
            self.inner.closes.fetch_add(1, Ordering::SeqCst);
            self.commit();
            Ok(())
        }
        fn last_write_delivered(&self) -> bool {
            self.buffer.is_empty()
        }
        fn kind(&self) -> SinkType {
            SinkType::Memory
        }
    }

    #[tokio::test]
    async fn run_discovery_closes_the_sink_once_at_end_of_stream() {
        let port = open_loopback_port().await;
        let scenario = scenario_for_port(port);

        let sink = Box::new(BatchingSink::new());
        let handle = sink.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(RunOptions::new(&scenario).resolver(resolver).sink(sink))
            .await
            .expect("run_discovery");
        assert_eq!(summary.records_emitted, 1);
        assert_eq!(
            handle.closes.load(Ordering::SeqCst),
            1,
            "the pipeline must close the sink exactly once at end-of-stream"
        );
        assert_eq!(
            handle.flushes.load(Ordering::SeqCst),
            0,
            "the terminal drain is close(), not flush()"
        );
    }

    #[tokio::test]
    async fn run_discovery_close_drains_a_batched_sink() {
        let port = open_loopback_port().await;
        let scenario = scenario_for_port(port);

        let sink = Box::new(BatchingSink::new());
        let handle = sink.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(RunOptions::new(&scenario).resolver(resolver).sink(sink))
            .await
            .expect("run_discovery");
        assert_eq!(summary.records_emitted, 1);
        let committed = handle.committed.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            committed.len(),
            1,
            "a record buffered during write must be delivered by close(), not lost"
        );
    }

    #[tokio::test]
    async fn pipeline_correlates_multi_ip_device_via_shared_sysname_and_mac() {
        use crate::fuser::IdentityHints;
        use crate::model::outcome::{ProbeKind, Signal};
        use std::time::SystemTime;

        // Stand up an IdentityFuser directly and drive it with hand-built outcomes.
        // The full run_discovery path is exercised elsewhere; here we assert the fuser
        // composes correctly at the pipeline boundary.
        let sysname = Signal::SnmpSysName("core-sw01".into());
        let mac = "aa:bb:cc:11:22:33";
        let outcomes = vec![
            ProbeOutcome {
                lldp: None,
                gnmi_endpoint: None,
                kind: ProbeKind::Snmp,
                target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: vec![Signal::Mac(mac.into()), sysname.clone()],
                fault: None,
            },
            ProbeOutcome {
                lldp: None,
                gnmi_endpoint: None,
                kind: ProbeKind::Snmp,
                target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: vec![Signal::Mac(mac.into()), sysname.clone()],
                fault: None,
            },
            ProbeOutcome {
                lldp: None,
                gnmi_endpoint: None,
                kind: ProbeKind::Snmp,
                target_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: vec![Signal::Mac(mac.into()), sysname.clone()],
                fault: None,
            },
        ];
        let fuser_cfg = FuserConfig::Identity {
            identity_hints: IdentityHints::default(),
            inner: Box::new(FuserConfig::Direct {
                include_unreachable: None,
                confidence_baseline: None,
                confidence_per_signal: None,
            }),
        };
        let mut f = create_fuser(&fuser_cfg).expect("create");
        let records = crate::fuser::drive_fuser(f.as_mut(), outcomes).expect("drive");
        assert_eq!(records.len(), 1, "three IPs share sysName+MAC, one record");
        let r = &records[0];
        assert_eq!(r.mgmt_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        let alt_addresses: Vec<IpAddr> = r.alt_ips.iter().map(|a| a.address).collect();
        assert_eq!(
            alt_addresses,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            ]
        );
        assert!(r.possible_alias_of.is_none());
    }

    fn role_rule_on_port(port: u16) -> ClassifierConfig {
        ClassifierConfig::Rules {
            merge_mode: MergeMode::Extend,
            platform_rules: Vec::new(),
            role_rules: vec![crate::classifier::RoleRule::PortsOpen {
                ports: vec![port],
                role: "test_host".to_string(),
            }],
        }
    }

    async fn scan_open_loopback_port(
        port: u16,
        classifier: Option<ClassifierConfig>,
        fuser: Option<FuserConfig>,
    ) -> DeviceRecord {
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                classifier,
                fuser,
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem)),
        )
        .await
        .expect("run_discovery");
        assert_eq!(summary.records_emitted, 1);
        let lines = handle.ndjson_lines();
        assert_eq!(lines.len(), 1);
        serde_json::from_str(&lines[0]).expect("parse json")
    }

    #[tokio::test]
    async fn pipeline_runs_classifier_after_fuser() {
        let port = open_loopback_port().await;
        let record = scan_open_loopback_port(port, Some(role_rule_on_port(port)), None).await;
        assert_eq!(record.role.as_deref(), Some("test_host"));
    }

    #[tokio::test]
    async fn pipeline_classifies_the_records_the_identity_fuser_holds_until_finish() {
        let port = open_loopback_port().await;
        let fuser = FuserConfig::Identity {
            identity_hints: crate::fuser::IdentityHints::default(),
            inner: Box::new(FuserConfig::Direct {
                include_unreachable: None,
                confidence_baseline: None,
                confidence_per_signal: None,
            }),
        };
        let record =
            scan_open_loopback_port(port, Some(role_rule_on_port(port)), Some(fuser)).await;
        assert_eq!(
            record.role.as_deref(),
            Some("test_host"),
            "identity fuser emits every record from finish(), so the tail loop must classify too"
        );
    }

    fn classified_by_default(signals: Vec<crate::model::Signal>) -> DeviceRecord {
        let classifier =
            create_classifier(&crate::classifier::default_classifier_config()).expect("classifier");
        let mut record = DeviceRecord {
            identity_key: crate::model::IdentityKey::new("ip:10.0.0.1").expect("identity"),
            mgmt_ip: None,
            mac: None,
            manufacturer: None,
            model: None,
            product_family: None,
            platform: None,
            os_version: None,
            ssh_version: None,
            http_server: None,
            http_version: None,
            role: None,
            confidence: crate::model::Confidence::new(0.0).expect("confidence"),
            last_seen: std::time::SystemTime::UNIX_EPOCH,
            signals,
            probe_kinds: Vec::new(),
            schema_version: crate::model::CURRENT_SCHEMA_VERSION.to_string(),
            schema_id: crate::model::CURRENT_SCHEMA_ID.to_string(),
            alt_ips: Vec::new(),
            possible_alias_of: None,
            scan_metadata: Arc::new(ScanMetadata::default()),
        };
        classifier.classify(&mut record).expect("classify ok");
        record
    }

    #[test]
    fn default_classifier_reaches_the_baked_platform_table() {
        let record = classified_by_default(vec![crate::model::Signal::SnmpSysDescr(
            "Cisco IOS Software, C3560E Software, Version 15.7(3)M, RELEASE".to_string(),
        )]);
        assert_eq!(record.platform.as_deref(), Some("cisco_ios"));
        assert_eq!(record.os_version.as_deref(), Some("15.7"));
    }

    #[test]
    fn default_classifier_reaches_the_baked_role_table() {
        let record = classified_by_default(vec![
            crate::model::Signal::OpenPort(22),
            crate::model::Signal::OpenPort(179),
        ]);
        assert_eq!(record.role.as_deref(), Some("router"));
    }

    #[test]
    fn default_classifier_leaves_role_null_for_a_lone_open_port() {
        let record = classified_by_default(vec![crate::model::Signal::OpenPort(443)]);
        assert!(
            record.role.is_none(),
            "a single open port is a guess; the default table must not assign a role from it"
        );
    }

    #[cfg(feature = "ssh")]
    async fn spawn_ssh_banner_stub(banner: &'static str) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    let _ = stream.write_all(banner.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        port
    }

    #[cfg(feature = "ssh")]
    async fn scan_ssh_banner_stub(classifier: Option<ClassifierConfig>) -> DeviceRecord {
        let port = spawn_ssh_banner_stub("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n").await;
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                classifier,
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::Ssh { ports: vec![port] }],
        };

        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem)),
        )
        .await
        .expect("run_discovery");
        let lines = handle.ndjson_lines();
        assert_eq!(lines.len(), 1);
        serde_json::from_str(&lines[0]).expect("parse json")
    }

    #[cfg(feature = "ssh")]
    #[tokio::test]
    async fn scan_without_classifier_config_reads_ssh_version_not_platform() {
        let record = scan_ssh_banner_stub(None).await;
        assert_eq!(record.ssh_version.as_deref(), Some("OpenSSH_9.6p1"));
        assert!(record.platform.is_none());
        assert!(record.os_version.is_none());
    }

    #[cfg(feature = "ssh")]
    #[tokio::test]
    async fn explicit_noop_classifier_leaves_an_ssh_banner_unclassified() {
        let record = scan_ssh_banner_stub(Some(ClassifierConfig::Noop)).await;
        assert!(record.platform.is_none());
        assert!(record.os_version.is_none());
        assert!(record.ssh_version.is_none());
    }

    #[tokio::test]
    async fn run_discovery_stamps_scan_metadata_on_every_record() {
        let port_a = open_loopback_port().await;
        let port_b = open_loopback_port().await;

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                name: Some("integration-lab".into()),
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![
                ProberConfig::TcpConnect {
                    ports: vec![port_a],
                },
                ProberConfig::TcpConnect {
                    ports: vec![port_b],
                },
            ],
        };

        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .resolver(resolver)
                .sink(Box::new(mem)),
        )
        .await
        .expect("run_discovery");
        assert!(summary.records_emitted >= 1);

        let lines = handle.ndjson_lines();
        assert!(!lines.is_empty());
        let records: Vec<crate::model::DeviceRecord> = lines
            .iter()
            .map(|l| serde_json::from_str(l).expect("parse record"))
            .collect();
        let first = &records[0];
        assert_eq!(first.scan_metadata.scan_id.len(), 26);
        assert_eq!(
            first.scan_metadata.scenario_name.as_deref(),
            Some("integration-lab")
        );
        for r in &records {
            assert_eq!(
                r.scan_metadata.scan_id, first.scan_metadata.scan_id,
                "all records must share the same scan_id"
            );
            assert_eq!(
                r.scan_metadata.initiated_at, first.scan_metadata.initiated_at,
                "all records must share the same initiated_at"
            );
            assert_eq!(r.schema_version, crate::model::CURRENT_SCHEMA_VERSION);
            assert_eq!(r.schema_id, crate::model::CURRENT_SCHEMA_ID);
        }
    }

    #[test]
    fn stamp_scan_metadata_shares_one_arc_across_records() {
        fn stub() -> DeviceRecord {
            DeviceRecord {
                identity_key: crate::model::IdentityKey::new("id").expect("identity"),
                mgmt_ip: None,
                mac: None,
                manufacturer: None,
                model: None,
                product_family: None,
                platform: None,
                os_version: None,
                ssh_version: None,
                http_server: None,
                http_version: None,
                role: None,
                confidence: crate::model::Confidence::new(0.0).expect("confidence"),
                last_seen: std::time::SystemTime::UNIX_EPOCH,
                signals: Vec::new(),
                probe_kinds: Vec::new(),
                schema_version: crate::model::CURRENT_SCHEMA_VERSION.to_string(),
                schema_id: crate::model::CURRENT_SCHEMA_ID.to_string(),
                alt_ips: Vec::new(),
                possible_alias_of: None,
                scan_metadata: Arc::new(ScanMetadata::default()),
            }
        }

        let scan_metadata = Arc::new(ScanMetadata::new(&scenario_with_probers(vec![
            ProberConfig::TcpConnect { ports: vec![22] },
        ])));
        let mut first = stub();
        let mut second = stub();
        stamp_scan_metadata(&mut first, &scan_metadata);
        stamp_scan_metadata(&mut second, &scan_metadata);

        assert!(
            Arc::ptr_eq(&first.scan_metadata, &second.scan_metadata),
            "every record from one scan must share ONE Arc<ScanMetadata>, not a per-record clone"
        );
    }

    struct MutualLldpProber {
        cx: &'static str,
        cy: &'static str,
    }

    #[async_trait::async_trait]
    impl Prober for MutualLldpProber {
        fn kind(&self) -> ProbeKind {
            ProbeKind::Lldp
        }
        async fn probe(
            &self,
            target: &ResolvedTarget,
            _ctx: &ProbeCtx,
        ) -> Result<ProbeOutcome, RastreoError> {
            let last = match target.ip {
                IpAddr::V4(v4) => v4.octets()[3],
                IpAddr::V6(_) => 0,
            };
            let (local, remote) = if last == 1 {
                (self.cx, self.cy)
            } else {
                (self.cy, self.cx)
            };
            Ok(ProbeOutcome {
                kind: ProbeKind::Lldp,
                target_ip: target.ip,
                timestamp: std::time::SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: vec![crate::model::Signal::Mac(local.into())],
                fault: None,
                lldp: Some(crate::model::LldpObservation {
                    local_chassis_id: local.into(),
                    local_chassis_subtype: 4,
                    neighbors: vec![crate::model::LldpNeighbor {
                        local_port: "Gi0/1".into(),
                        remote_chassis_id: remote.into(),
                        remote_chassis_subtype: 4,
                        remote_port_id: "Gi0/2".into(),
                        remote_port_subtype: 5,
                        remote_port_desc: None,
                        remote_sys_name: None,
                    }],
                    discovered_via: "lldp".into(),
                }),
                gnmi_endpoint: None,
            })
        }
    }

    #[tokio::test]
    async fn pipeline_emits_one_link_for_two_mutually_lldp_devices() {
        let cx = "aaaaaaaaaaaa";
        let cy = "bbbbbbbbbbbb";
        let resolved: Vec<ResolvedTarget> = (1u8..=2)
            .map(|i| {
                let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
                ResolvedTarget {
                    ip,
                    original: Target::Ip(ip),
                    resolved_at: std::time::SystemTime::UNIX_EPOCH,
                }
            })
            .collect();

        let scan_metadata = Arc::new(ScanMetadata {
            scan_id: "0123456789ABCDEFGHJKMNPQRS".to_string(),
            ..ScanMetadata::default()
        });
        let probers: Vec<Arc<dyn Prober>> = vec![Arc::new(MutualLldpProber { cx, cy })];
        let scheduler = BoundedScheduler::new(8);
        let mut fuser = create_fuser(&FuserConfig::Direct {
            include_unreachable: None,
            confidence_baseline: None,
            confidence_per_signal: None,
        })
        .expect("fuser");
        let classifier = create_classifier(&ClassifierConfig::Noop).expect("classifier");
        let encoder = create_encoder(&EncoderConfig::Ndjson).expect("encoder");
        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let mut sink: Box<dyn Sink> = Box::new(mem);
        let peak = AtomicUsize::new(0);
        let scan_span = tracing::info_span!("scan");
        let summary = stream_discovery(
            &scheduler,
            probers,
            Box::new(resolved.into_iter()),
            ProbeCtx::new(Duration::from_millis(100), 0),
            watch::channel(false).1,
            fuser.as_mut(),
            classifier.as_ref(),
            encoder.as_ref(),
            sink.as_mut(),
            &scan_metadata,
            2,
            Instant::now(),
            0,
            &peak,
            &scan_span,
            None,
            None,
        )
        .await
        .expect("stream summary");

        assert_eq!(
            summary.records_emitted, 2,
            "one device record per probed host"
        );
        assert_eq!(
            summary.links_emitted, 1,
            "the mutual link collapses to one record"
        );

        let lines = handle.ndjson_lines();
        let values: Vec<serde_json::Value> = lines
            .iter()
            .map(|l| serde_json::from_str(l).expect("json line"))
            .collect();
        let link_positions: Vec<usize> = values
            .iter()
            .enumerate()
            .filter(|(_, v)| {
                v["schema_id"]
                    .as_str()
                    .is_some_and(|id| id.contains("link-record-v1.json"))
            })
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            link_positions,
            vec![values.len() - 1],
            "the link flushes last"
        );

        let link: crate::model::LinkRecord =
            serde_json::from_str(&lines[values.len() - 1]).expect("parse link");
        assert_eq!(link.scan_metadata.scan_id, "0123456789ABCDEFGHJKMNPQRS");
        let chassis: std::collections::BTreeSet<&str> =
            [link.a.chassis_id.as_str(), link.b.chassis_id.as_str()]
                .into_iter()
                .collect();
        assert_eq!(
            chassis,
            [cx, cy]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
        );
        assert!(link.a.identity_key.is_some());
        assert!(link.b.identity_key.is_some());
    }

    mod streaming_differential {
        use super::*;

        use std::time::SystemTime;

        use crate::model::Signal;

        const FAULT_P1_T2: &str = "fault-pass1-target2";
        const FAULT_P2_T0: &str = "fault-pass2-target0";

        type ProbeSetup = (Vec<Arc<dyn Prober>>, Vec<ResolvedTarget>);
        type MatrixSetup = (&'static str, Vec<Arc<dyn Prober>>, Vec<ResolvedTarget>);

        #[derive(Clone)]
        enum Resp {
            Reachable(Vec<Signal>),
            Dark,
            Fault(ProbeErrorKind, &'static str),
            Err(&'static str),
        }

        struct ScriptedProber {
            kind: ProbeKind,
            responses: Vec<Resp>,
        }

        #[async_trait::async_trait]
        impl Prober for ScriptedProber {
            fn kind(&self) -> ProbeKind {
                self.kind
            }

            async fn probe(
                &self,
                target: &ResolvedTarget,
                _ctx: &ProbeCtx,
            ) -> Result<ProbeOutcome, RastreoError> {
                let idx = match target.ip {
                    IpAddr::V4(v4) => v4.octets()[3] as usize,
                    IpAddr::V6(_) => 0,
                };
                match &self.responses[idx] {
                    Resp::Reachable(signals) => Ok(ProbeOutcome {
                        lldp: None,
                        gnmi_endpoint: None,
                        kind: self.kind,
                        target_ip: target.ip,
                        timestamp: SystemTime::UNIX_EPOCH,
                        reachable: true,
                        signals: signals.clone(),
                        fault: None,
                    }),
                    Resp::Dark => Ok(ProbeOutcome {
                        lldp: None,
                        gnmi_endpoint: None,
                        kind: self.kind,
                        target_ip: target.ip,
                        timestamp: SystemTime::UNIX_EPOCH,
                        reachable: false,
                        signals: Vec::new(),
                        fault: None,
                    }),
                    Resp::Fault(kind, detail) => Ok(ProbeOutcome {
                        lldp: None,
                        gnmi_endpoint: None,
                        kind: self.kind,
                        target_ip: target.ip,
                        timestamp: SystemTime::UNIX_EPOCH,
                        reachable: true,
                        signals: Vec::new(),
                        fault: Some(ProbeFault::new(*kind, *detail)),
                    }),
                    Resp::Err(msg) => Err(RastreoError::Probe(crate::error::ProbeError::Other(
                        (*msg).to_string(),
                    ))),
                }
            }
        }

        fn scripted(kind: ProbeKind, responses: Vec<Resp>) -> Arc<dyn Prober> {
            Arc::new(ScriptedProber { kind, responses })
        }

        fn resolved_n(n: u8) -> Vec<ResolvedTarget> {
            (0..n)
                .map(|i| {
                    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
                    ResolvedTarget {
                        ip,
                        original: Target::Ip(ip),
                        resolved_at: SystemTime::UNIX_EPOCH,
                    }
                })
                .collect()
        }

        fn resolved_many(n: usize) -> Vec<ResolvedTarget> {
            (0..n as u32)
                .map(|i| {
                    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, (i & 0xff) as u8));
                    ResolvedTarget {
                        ip,
                        original: Target::Ip(ip),
                        resolved_at: SystemTime::UNIX_EPOCH,
                    }
                })
                .collect()
        }

        fn direct_cfg() -> FuserConfig {
            FuserConfig::Direct {
                include_unreachable: None,
                confidence_baseline: None,
                confidence_per_signal: None,
            }
        }

        fn identity_cfg() -> FuserConfig {
            FuserConfig::Identity {
                identity_hints: crate::fuser::IdentityHints::default(),
                inner: Box::new(direct_cfg()),
            }
        }

        async fn run_streaming(
            probers: Vec<Arc<dyn Prober>>,
            resolved: Vec<ResolvedTarget>,
            fuser_cfg: &FuserConfig,
            scan_metadata: &Arc<ScanMetadata>,
        ) -> (Result<DiscoverySummary, RastreoError>, Vec<String>) {
            let ctx = ProbeCtx::new(Duration::from_millis(100), 0);
            let scheduler = BoundedScheduler::new(8);
            let mut fuser = create_fuser(fuser_cfg).expect("fuser");
            let classifier = create_classifier(&ClassifierConfig::Noop).expect("classifier");
            let encoder = create_encoder(&EncoderConfig::Ndjson).expect("encoder");
            let mem = crate::sink::MemorySink::new();
            let handle = mem.handle();
            let mut sink: Box<dyn Sink> = Box::new(mem);
            let targets_resolved = resolved.len();
            let start = Instant::now();
            let peak = AtomicUsize::new(0);
            let scan_span = tracing::info_span!("scan");
            let result = stream_discovery(
                &scheduler,
                probers,
                Box::new(resolved.into_iter()),
                ctx,
                watch::channel(false).1,
                fuser.as_mut(),
                classifier.as_ref(),
                encoder.as_ref(),
                sink.as_mut(),
                scan_metadata,
                targets_resolved,
                start,
                0,
                &peak,
                &scan_span,
                None,
                None,
            )
            .await;
            (result, handle.ndjson_lines())
        }

        async fn run_batch(
            probers: Vec<Arc<dyn Prober>>,
            resolved: Vec<ResolvedTarget>,
            fuser_cfg: &FuserConfig,
            scan_metadata: &Arc<ScanMetadata>,
        ) -> (Result<DiscoverySummary, RastreoError>, Vec<String>) {
            let ctx = ProbeCtx::new(Duration::from_millis(100), 0);
            let scheduler = BoundedScheduler::new(8);
            let prober_kinds: Vec<ProbeKind> = probers.iter().map(|p| p.kind()).collect();
            let mut fuser = create_fuser(fuser_cfg).expect("fuser");
            let classifier = create_classifier(&ClassifierConfig::Noop).expect("classifier");
            let encoder = create_encoder(&EncoderConfig::Ndjson).expect("encoder");
            let mem = crate::sink::MemorySink::new();
            let handle = mem.handle();
            let mut sink: Box<dyn Sink> = Box::new(mem);
            let targets_resolved = resolved.len();
            let start = Instant::now();
            let (scans, cancelled) =
                collect_scans_sorted(&scheduler, probers, resolved, ctx, watch::channel(false).1)
                    .await;
            let acc = accumulate_scans(scans, &prober_kinds, cancelled);
            let result = finish_discovery_ref(
                acc,
                fuser.as_mut(),
                classifier.as_ref(),
                encoder.as_ref(),
                sink.as_mut(),
                scan_metadata,
                targets_resolved,
                start,
            )
            .await;
            (result, handle.ndjson_lines())
        }

        async fn run_streaming_with(
            probers: Vec<Arc<dyn Prober>>,
            resolved: Vec<ResolvedTarget>,
            sink: Box<dyn Sink>,
            max_concurrent: usize,
            scan_metadata: &Arc<ScanMetadata>,
            peak: &AtomicUsize,
        ) -> Result<DiscoverySummary, RastreoError> {
            let ctx = ProbeCtx::new(Duration::from_millis(500), 0);
            let scheduler = BoundedScheduler::new(max_concurrent);
            let mut fuser = create_fuser(&direct_cfg()).expect("fuser");
            let classifier = create_classifier(&ClassifierConfig::Noop).expect("classifier");
            let encoder = create_encoder(&EncoderConfig::Ndjson).expect("encoder");
            let mut sink = sink;
            let targets_resolved = resolved.len();
            let start = Instant::now();
            let scan_span = tracing::info_span!("scan");
            stream_discovery(
                &scheduler,
                probers,
                Box::new(resolved.into_iter()),
                ctx,
                watch::channel(false).1,
                fuser.as_mut(),
                classifier.as_ref(),
                encoder.as_ref(),
                sink.as_mut(),
                scan_metadata,
                targets_resolved,
                start,
                0,
                peak,
                &scan_span,
                None,
                None,
            )
            .await
        }

        async fn run_batch_with(
            probers: Vec<Arc<dyn Prober>>,
            resolved: Vec<ResolvedTarget>,
            sink: Box<dyn Sink>,
            max_concurrent: usize,
            scan_metadata: &Arc<ScanMetadata>,
        ) -> Result<DiscoverySummary, RastreoError> {
            let ctx = ProbeCtx::new(Duration::from_millis(500), 0);
            let scheduler = BoundedScheduler::new(max_concurrent);
            let prober_kinds: Vec<ProbeKind> = probers.iter().map(|p| p.kind()).collect();
            let mut fuser = create_fuser(&direct_cfg()).expect("fuser");
            let classifier = create_classifier(&ClassifierConfig::Noop).expect("classifier");
            let encoder = create_encoder(&EncoderConfig::Ndjson).expect("encoder");
            let mut sink = sink;
            let targets_resolved = resolved.len();
            let start = Instant::now();
            let (scans, cancelled) =
                collect_scans_sorted(&scheduler, probers, resolved, ctx, watch::channel(false).1)
                    .await;
            let acc = accumulate_scans(scans, &prober_kinds, cancelled);
            finish_discovery_ref(
                acc,
                fuser.as_mut(),
                classifier.as_ref(),
                encoder.as_ref(),
                sink.as_mut(),
                scan_metadata,
                targets_resolved,
                start,
            )
            .await
        }

        fn assert_summaries_match(new: &DiscoverySummary, batch: &DiscoverySummary, label: &str) {
            assert_eq!(
                new.targets_resolved, batch.targets_resolved,
                "{label}: targets_resolved"
            );
            assert_eq!(
                new.probe_attempts, batch.probe_attempts,
                "{label}: probe_attempts"
            );
            assert_eq!(
                new.records_emitted, batch.records_emitted,
                "{label}: records_emitted"
            );
            assert_eq!(
                new.links_emitted, batch.links_emitted,
                "{label}: links_emitted"
            );
            assert_eq!(
                new.profiles_emitted, batch.profiles_emitted,
                "{label}: profiles_emitted"
            );
            assert_eq!(
                new.error_counts, batch.error_counts,
                "{label}: error_counts"
            );
            assert_eq!(
                new.probes_by_kind, batch.probes_by_kind,
                "{label}: probes_by_kind"
            );
            assert_eq!(new.dlq_records, batch.dlq_records, "{label}: dlq_records");
            assert_eq!(
                new.dlq_records_by_type_and_class, batch.dlq_records_by_type_and_class,
                "{label}: dlq_records_by_type_and_class"
            );
            assert_eq!(new.sink_type, batch.sink_type, "{label}: sink_type");
            assert_eq!(new.cancelled, batch.cancelled, "{label}: cancelled");
            assert_eq!(
                new.first_probe_error, batch.first_probe_error,
                "{label}: first_probe_error"
            );
            // elapsed intentionally excluded — wall-clock differs between the two runs.
        }

        fn parse_link_records(lines: &[String]) -> Vec<crate::model::LinkRecord> {
            lines
                .iter()
                .filter_map(|line| {
                    let value: serde_json::Value = serde_json::from_str(line).expect("json line");
                    let is_link = value["schema_id"]
                        .as_str()
                        .is_some_and(|id| id.contains("link-record-v1.json"));
                    is_link.then(|| serde_json::from_str(line).expect("parse link record"))
                })
                .collect()
        }

        fn parse_profile_records(lines: &[String]) -> Vec<crate::model::CollectionProfileRecord> {
            lines
                .iter()
                .filter_map(|line| {
                    let value: serde_json::Value = serde_json::from_str(line).expect("json line");
                    let is_profile = value["schema_id"]
                        .as_str()
                        .is_some_and(|id| id.contains("collection-profile-record-v1.json"));
                    is_profile.then(|| serde_json::from_str(line).expect("parse profile record"))
                })
                .collect()
        }

        fn first_probe_error_stress_setup() -> ProbeSetup {
            let probers = vec![
                scripted(
                    ProbeKind::TcpConnect,
                    vec![
                        Resp::Reachable(vec![Signal::OpenPort(22)]),
                        Resp::Reachable(vec![Signal::OpenPort(22)]),
                        Resp::Reachable(vec![Signal::OpenPort(22)]),
                    ],
                ),
                scripted(
                    ProbeKind::Http,
                    vec![
                        Resp::Reachable(vec![Signal::HttpBanner("nginx".into())]),
                        Resp::Reachable(vec![Signal::HttpBanner("nginx".into())]),
                        Resp::Fault(ProbeErrorKind::PermissionDenied, FAULT_P1_T2),
                    ],
                ),
                scripted(
                    ProbeKind::Snmp,
                    vec![
                        Resp::Fault(ProbeErrorKind::DecodeFailed, FAULT_P2_T0),
                        Resp::Reachable(vec![Signal::SnmpSysName("sw".into())]),
                        Resp::Reachable(vec![Signal::SnmpSysName("sw".into())]),
                    ],
                ),
            ];
            (probers, resolved_n(3))
        }

        // Emits a gNMI capability outcome per target so the differential harness exercises the
        // profile second stream, not just links. The surfaced endpoint is what the assembler reads.
        struct GnmiCapabilityProber;

        #[async_trait::async_trait]
        impl Prober for GnmiCapabilityProber {
            fn kind(&self) -> ProbeKind {
                ProbeKind::Gnmi
            }
            async fn probe(
                &self,
                target: &ResolvedTarget,
                _ctx: &ProbeCtx,
            ) -> Result<ProbeOutcome, RastreoError> {
                Ok(ProbeOutcome {
                    kind: ProbeKind::Gnmi,
                    target_ip: target.ip,
                    timestamp: SystemTime::UNIX_EPOCH,
                    reachable: true,
                    signals: vec![
                        Signal::GnmiVersion("0.10.0".into()),
                        Signal::GnmiSupportedModel(
                            "openconfig-interfaces 3.0.0 (OpenConfig)".into(),
                        ),
                        Signal::GnmiSupportedEncoding("JSON_IETF".into()),
                    ],
                    fault: None,
                    lldp: None,
                    gnmi_endpoint: Some(crate::model::GnmiEndpoint {
                        port: 57400,
                        transport: crate::model::Transport::Tls,
                        advertised_encodings: vec!["JSON_IETF".into(), "PROTO".into()],
                    }),
                })
            }
        }

        fn matrix_setups() -> Vec<MatrixSetup> {
            let (stress_probers, stress_targets) = first_probe_error_stress_setup();
            vec![
                (
                    "empty",
                    vec![scripted(ProbeKind::TcpConnect, vec![Resp::Dark])],
                    resolved_n(0),
                ),
                (
                    "single_reachable",
                    vec![scripted(
                        ProbeKind::TcpConnect,
                        vec![Resp::Reachable(vec![Signal::OpenPort(22)])],
                    )],
                    resolved_n(1),
                ),
                (
                    "single_dark",
                    vec![scripted(ProbeKind::TcpConnect, vec![Resp::Dark])],
                    resolved_n(1),
                ),
                (
                    "multi_mixed_three_probers",
                    vec![
                        scripted(
                            ProbeKind::TcpConnect,
                            vec![
                                Resp::Reachable(vec![Signal::OpenPort(22)]),
                                Resp::Dark,
                                Resp::Reachable(vec![Signal::OpenPort(22)]),
                            ],
                        ),
                        scripted(
                            ProbeKind::Http,
                            vec![
                                Resp::Reachable(vec![Signal::HttpBanner("nginx".into())]),
                                Resp::Reachable(vec![Signal::HttpBanner("nginx".into())]),
                                Resp::Dark,
                            ],
                        ),
                        scripted(
                            ProbeKind::Snmp,
                            vec![
                                Resp::Dark,
                                Resp::Reachable(vec![Signal::SnmpSysName("sw".into())]),
                                Resp::Reachable(vec![Signal::SnmpSysName("sw".into())]),
                            ],
                        ),
                    ],
                    resolved_n(3),
                ),
                (
                    "faulted",
                    vec![scripted(
                        ProbeKind::TcpConnect,
                        vec![
                            Resp::Fault(ProbeErrorKind::DecodeFailed, "decode-t0"),
                            Resp::Reachable(vec![Signal::OpenPort(22)]),
                        ],
                    )],
                    resolved_n(2),
                ),
                (
                    "stray_err",
                    vec![scripted(
                        ProbeKind::TcpConnect,
                        vec![
                            Resp::Err("could not attempt"),
                            Resp::Reachable(vec![Signal::OpenPort(22)]),
                        ],
                    )],
                    resolved_n(2),
                ),
                (
                    "all_dark",
                    vec![scripted(
                        ProbeKind::TcpConnect,
                        vec![Resp::Dark, Resp::Dark, Resp::Dark],
                    )],
                    resolved_n(3),
                ),
                ("first_probe_error_stress", stress_probers, stress_targets),
                (
                    "mutual_lldp_link",
                    vec![Arc::new(MutualLldpProber {
                        cx: "aaaaaaaaaaaa",
                        cy: "bbbbbbbbbbbb",
                    })],
                    resolved_n(2),
                ),
                (
                    "gnmi_profile",
                    vec![Arc::new(GnmiCapabilityProber)],
                    resolved_n(2),
                ),
            ]
        }

        #[tokio::test]
        async fn streaming_matches_batch_across_matrix() {
            #[allow(unused_mut)]
            let mut fusers = vec![direct_cfg(), identity_cfg()];
            #[cfg(feature = "mib_enrichment")]
            fusers.push(FuserConfig::MibEnrichment {
                data_path: None,
                inner: Box::new(direct_cfg()),
            });

            for (label, probers, resolved) in matrix_setups() {
                for fuser_cfg in &fusers {
                    let scan_metadata = Arc::new(ScanMetadata::default());
                    let (summary_stream, records_stream) =
                        run_streaming(probers.clone(), resolved.clone(), fuser_cfg, &scan_metadata)
                            .await;
                    let (summary_batch, records_batch) =
                        run_batch(probers.clone(), resolved.clone(), fuser_cfg, &scan_metadata)
                            .await;
                    let summary_stream = summary_stream.expect("streaming summary");
                    let summary_batch = summary_batch.expect("batch summary");
                    assert_summaries_match(&summary_stream, &summary_batch, label);
                    assert_eq!(
                        records_stream, records_batch,
                        "{label}: streaming and batch pipelines must emit byte-identical records"
                    );
                    assert_eq!(
                        parse_link_records(&records_stream),
                        parse_link_records(&records_batch),
                        "{label}: streaming and batch pipelines must emit field-identical link records"
                    );
                    assert_eq!(
                        parse_profile_records(&records_stream),
                        parse_profile_records(&records_batch),
                        "{label}: streaming and batch pipelines must emit field-identical profile records"
                    );
                }
            }
        }

        #[tokio::test]
        async fn pipeline_emits_a_collection_profile_for_a_gnmi_capability_outcome() {
            let scan_metadata = Arc::new(ScanMetadata::default());
            let probers: Vec<Arc<dyn Prober>> = vec![Arc::new(GnmiCapabilityProber)];
            let (summary, records) =
                run_streaming(probers, resolved_n(1), &direct_cfg(), &scan_metadata).await;
            let summary = summary.expect("summary");
            assert_eq!(summary.profiles_emitted, 1);

            let profiles = parse_profile_records(&records);
            assert_eq!(profiles.len(), 1);
            let p = &profiles[0];
            assert_eq!(p.endpoint.address, "10.0.0.0");
            assert_eq!(p.endpoint.port, 57400);
            assert_eq!(p.endpoint.transport, crate::model::Transport::Tls);
            assert_eq!(
                p.confidence,
                crate::model::ProfileConfidence::AdvertisedOnly
            );

            let value: serde_json::Value = serde_json::to_value(p).expect("serialize");
            assert_eq!(value["collection"]["protocol"], "gnmi");
            let subs = value["collection"]["suggested_subscriptions"]
                .as_array()
                .expect("array");
            assert_eq!(
                subs.len(),
                3,
                "openconfig-interfaces expands to its curated paths"
            );
            assert!(subs.iter().all(|s| s["origin"] == "openconfig"
                && s["matched_model"] == "openconfig-interfaces 3.0.0 (OpenConfig)"));
            assert!(subs
                .iter()
                .any(|s| s["path"] == "/interfaces/interface/state/counters"
                    && s["mode"] == "sample"));
            assert!(subs
                .iter()
                .any(|s| s["path"] == "/interfaces/interface/state/oper-status"
                    && s["mode"] == "on_change"));

            let crate::model::Collection::Gnmi {
                encoding,
                supported_models,
                ..
            } = &p.collection;
            assert_eq!(encoding, "JSON_IETF");
            assert!(supported_models
                .iter()
                .any(|m| m.contains("openconfig-interfaces")));
        }

        // Inverted latency: target `idx` sleeps `n - idx` ms, so completion order is the exact
        // reverse of input order — the reorder buffer must hold the whole scan until target 0.
        struct InvertedLatencyProber {
            n: u8,
            mac: &'static str,
            sysname: &'static str,
        }

        #[async_trait::async_trait]
        impl Prober for InvertedLatencyProber {
            fn kind(&self) -> ProbeKind {
                ProbeKind::Snmp
            }
            async fn probe(
                &self,
                target: &ResolvedTarget,
                _ctx: &ProbeCtx,
            ) -> Result<ProbeOutcome, RastreoError> {
                let idx = match target.ip {
                    IpAddr::V4(v4) => v4.octets()[3],
                    IpAddr::V6(_) => 0,
                };
                tokio::time::sleep(Duration::from_millis((self.n - idx) as u64)).await;
                Ok(ProbeOutcome {
                    lldp: None,
                    gnmi_endpoint: None,
                    kind: ProbeKind::Snmp,
                    target_ip: target.ip,
                    timestamp: SystemTime::UNIX_EPOCH,
                    reachable: true,
                    signals: vec![
                        Signal::Mac(self.mac.into()),
                        Signal::SnmpSysName(self.sysname.into()),
                    ],
                    fault: None,
                })
            }
        }

        // `start_paused` auto-advances virtual time, so the distinct per-target sleeps resolve in a
        // fixed reverse order — deterministic, no wall-clock flake. direct catches a line-order
        // reorder bug; identity (all targets merge on shared MAC + sysName) catches a corrupted
        // merge — wrong mgmt_ip / alt_ips order — that a line-order-only check would miss.
        #[tokio::test(start_paused = true)]
        async fn streaming_matches_batch_under_out_of_order_completion() {
            const N: u8 = 6;
            let mac = "aa:bb:cc:00:11:22";
            let sysname = "core-sw";

            for fuser_cfg in [direct_cfg(), identity_cfg()] {
                let scan_metadata = Arc::new(ScanMetadata::default());
                let probers: Vec<Arc<dyn Prober>> =
                    vec![Arc::new(InvertedLatencyProber { n: N, mac, sysname })];
                let targets = resolved_n(N);

                let (summary_stream, records_stream) =
                    run_streaming(probers.clone(), targets.clone(), &fuser_cfg, &scan_metadata)
                        .await;
                let (summary_batch, records_batch) =
                    run_batch(probers, targets, &fuser_cfg, &scan_metadata).await;

                let summary_stream = summary_stream.expect("streaming summary");
                let summary_batch = summary_batch.expect("batch summary");
                assert_summaries_match(&summary_stream, &summary_batch, "out_of_order");
                assert!(
                    !records_stream.is_empty(),
                    "the scan must emit records so the byte-identical comparison is not vacuous"
                );
                assert_eq!(
                    records_stream, records_batch,
                    "completion order is the reverse of input order; streaming must reassemble input \
                     order and emit records byte-identical to the batch reference"
                );
            }
        }

        #[tokio::test]
        async fn streaming_first_probe_error_uses_prober_outer_min_key() {
            let (probers, resolved) = first_probe_error_stress_setup();
            let scan_metadata = Arc::new(ScanMetadata::default());
            let (summary, _) =
                run_streaming(probers, resolved, &direct_cfg(), &scan_metadata).await;
            let fault = summary
                .expect("summary")
                .first_probe_error
                .expect("a fault must be latched");
            assert_eq!(
                fault.detail, FAULT_P1_T2,
                "first_probe_error must be the prober-outer first fault (pass 1, target 2), \
                 not the target-outer first-seen fault (pass 2, target 0)"
            );
        }

        struct CountingReachableProber {
            probed: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl Prober for CountingReachableProber {
            fn kind(&self) -> ProbeKind {
                ProbeKind::TcpConnect
            }
            async fn probe(
                &self,
                target: &ResolvedTarget,
                _ctx: &ProbeCtx,
            ) -> Result<ProbeOutcome, RastreoError> {
                self.probed.fetch_add(1, Ordering::SeqCst);
                Ok(ProbeOutcome {
                    lldp: None,
                    gnmi_endpoint: None,
                    kind: ProbeKind::TcpConnect,
                    target_ip: target.ip,
                    timestamp: SystemTime::UNIX_EPOCH,
                    reachable: true,
                    signals: vec![Signal::OpenPort(22)],
                    fault: None,
                })
            }
        }

        fn counting_prober(probed: Arc<AtomicUsize>) -> Vec<Arc<dyn Prober>> {
            vec![Arc::new(CountingReachableProber { probed })]
        }

        #[derive(Default)]
        struct RecordingFailSinkInner {
            written: std::sync::Mutex<Vec<Vec<u8>>>,
            write_attempts: AtomicUsize,
        }

        struct RecordingFailSink {
            inner: Arc<RecordingFailSinkInner>,
            fail_on: usize,
        }

        impl RecordingFailSink {
            fn new(fail_on: usize) -> Self {
                Self {
                    inner: Arc::new(RecordingFailSinkInner::default()),
                    fail_on,
                }
            }
            fn handle(&self) -> Arc<RecordingFailSinkInner> {
                Arc::clone(&self.inner)
            }
        }

        #[async_trait::async_trait]
        impl Sink for RecordingFailSink {
            async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
                let n = self.inner.write_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if n == self.fail_on {
                    return Err(RastreoError::Sink(crate::sink::SinkError::new(
                        SinkErrorClass::WriteFailure,
                        std::io::Error::other("simulated write failure"),
                    )));
                }
                self.inner
                    .written
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(data.to_vec());
                Ok(())
            }
            async fn flush(&mut self) -> Result<(), RastreoError> {
                Ok(())
            }
            fn last_write_delivered(&self) -> bool {
                true
            }
            fn kind(&self) -> SinkType {
                SinkType::Memory
            }
        }

        // An emit error must not truncate the scan: streaming stops emitting but keeps draining, so
        // every target still probes and the metrics stay as complete as the batch pipeline's. The
        // probe-count assertion is the mutation guard — a stop-on-emit-error loop leaves the scan
        // partial and this test goes red.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn streaming_matches_batch_with_failing_sink() {
            const N: usize = 50;
            const FAIL_ON: usize = 5;
            const CAP: usize = 8;
            let targets = resolved_many(N);
            let scan_metadata = Arc::new(ScanMetadata::default());

            let probed_stream = Arc::new(AtomicUsize::new(0));
            let sink_stream = RecordingFailSink::new(FAIL_ON);
            let handle_stream = sink_stream.handle();
            let peak = AtomicUsize::new(0);
            let err_stream = run_streaming_with(
                counting_prober(Arc::clone(&probed_stream)),
                targets.clone(),
                Box::new(sink_stream),
                CAP,
                &scan_metadata,
                &peak,
            )
            .await
            .expect_err("failing sink must surface an error");

            let probed_batch = Arc::new(AtomicUsize::new(0));
            let sink_batch = RecordingFailSink::new(FAIL_ON);
            let handle_batch = sink_batch.handle();
            let err_batch = run_batch_with(
                counting_prober(Arc::clone(&probed_batch)),
                targets.clone(),
                Box::new(sink_batch),
                CAP,
                &scan_metadata,
            )
            .await
            .expect_err("failing sink must surface an error");

            assert_eq!(
                err_stream.sink_error_class(),
                Some(SinkErrorClass::WriteFailure)
            );
            assert_eq!(
                err_batch.sink_error_class(),
                Some(SinkErrorClass::WriteFailure)
            );

            assert_eq!(
                probed_batch.load(Ordering::SeqCst),
                N,
                "batch drains the whole scan before emit"
            );
            assert_eq!(
                probed_stream.load(Ordering::SeqCst),
                N,
                "streaming must keep draining after the emit error so metrics stay complete; \
                 a stop-on-error loop probes only ~cap+window of the {N} targets"
            );

            let written_stream = handle_stream
                .written
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let written_batch = handle_batch
                .written
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            assert_eq!(
                written_stream.len(),
                FAIL_ON - 1,
                "records_emitted equals the successful writes before the failure"
            );
            assert_eq!(
                written_stream, written_batch,
                "streaming and batch write byte-identical records up to the failure"
            );
        }

        struct JitterProber;

        #[async_trait::async_trait]
        impl Prober for JitterProber {
            fn kind(&self) -> ProbeKind {
                ProbeKind::TcpConnect
            }
            async fn probe(
                &self,
                target: &ResolvedTarget,
                _ctx: &ProbeCtx,
            ) -> Result<ProbeOutcome, RastreoError> {
                let last = match target.ip {
                    IpAddr::V4(v4) => v4.octets()[3] as u64,
                    IpAddr::V6(_) => 0,
                };
                // Small per-target jitter so completions interleave within the concurrency window.
                tokio::time::sleep(Duration::from_micros((last % 4) * 50)).await;
                Ok(ProbeOutcome {
                    lldp: None,
                    gnmi_endpoint: None,
                    kind: ProbeKind::TcpConnect,
                    target_ip: target.ip,
                    timestamp: SystemTime::UNIX_EPOCH,
                    reachable: true,
                    signals: vec![Signal::OpenPort(22)],
                    fault: None,
                })
            }
        }

        struct SlowSink {
            delegate: crate::sink::MemorySink,
        }

        #[async_trait::async_trait]
        impl Sink for SlowSink {
            async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
                tokio::time::sleep(Duration::from_micros(200)).await;
                self.delegate.write(data).await
            }
            async fn flush(&mut self) -> Result<(), RastreoError> {
                self.delegate.flush().await
            }
            fn last_write_delivered(&self) -> bool {
                self.delegate.last_write_delivered()
            }
            fn kind(&self) -> SinkType {
                SinkType::Memory
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn streaming_bounds_reorder_and_channel_under_slow_sink() {
            const N: usize = 500;
            const CAP: usize = 8;
            let targets = resolved_many(N);
            let scan_metadata = Arc::new(ScanMetadata::default());
            let peak = AtomicUsize::new(0);
            let sink = SlowSink {
                delegate: crate::sink::MemorySink::new(),
            };
            let summary = run_streaming_with(
                vec![Arc::new(JitterProber)],
                targets,
                Box::new(sink),
                CAP,
                &scan_metadata,
                &peak,
            )
            .await
            .expect("streaming summary");

            assert_eq!(summary.records_emitted, N, "every target emitted");
            let observed = peak.load(Ordering::SeqCst);
            assert!(
                observed <= 3 * CAP,
                "reorder buffer peak {observed} must stay within the concurrency window (channel is \
                 separately bounded by cap = {CAP}), never the {N} targets"
            );
        }

        struct FirstTargetFastProber {
            probes_done: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl Prober for FirstTargetFastProber {
            fn kind(&self) -> ProbeKind {
                ProbeKind::TcpConnect
            }
            async fn probe(
                &self,
                target: &ResolvedTarget,
                _ctx: &ProbeCtx,
            ) -> Result<ProbeOutcome, RastreoError> {
                let last = match target.ip {
                    IpAddr::V4(v4) => v4.octets()[3],
                    IpAddr::V6(_) => 0,
                };
                if last != 0 {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                self.probes_done.fetch_add(1, Ordering::SeqCst);
                Ok(ProbeOutcome {
                    lldp: None,
                    gnmi_endpoint: None,
                    kind: ProbeKind::TcpConnect,
                    target_ip: target.ip,
                    timestamp: SystemTime::UNIX_EPOCH,
                    reachable: true,
                    signals: vec![Signal::OpenPort(22)],
                    fault: None,
                })
            }
        }

        struct FirstWriteProbeSink {
            delegate: crate::sink::MemorySink,
            probes_done: Arc<AtomicUsize>,
            probes_at_first_write: Arc<AtomicUsize>,
            seen_first: bool,
        }

        #[async_trait::async_trait]
        impl Sink for FirstWriteProbeSink {
            async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
                if !self.seen_first {
                    self.seen_first = true;
                    self.probes_at_first_write
                        .store(self.probes_done.load(Ordering::SeqCst), Ordering::SeqCst);
                }
                self.delegate.write(data).await
            }
            async fn flush(&mut self) -> Result<(), RastreoError> {
                self.delegate.flush().await
            }
            fn last_write_delivered(&self) -> bool {
                self.delegate.last_write_delivered()
            }
            fn kind(&self) -> SinkType {
                SinkType::Memory
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn streaming_emits_first_record_before_scan_completes() {
            const N: u8 = 6;
            let targets = resolved_n(N);
            let scan_metadata = Arc::new(ScanMetadata::default());
            let probes_done = Arc::new(AtomicUsize::new(0));
            let probes_at_first_write = Arc::new(AtomicUsize::new(usize::MAX));
            let sink = FirstWriteProbeSink {
                delegate: crate::sink::MemorySink::new(),
                probes_done: Arc::clone(&probes_done),
                probes_at_first_write: Arc::clone(&probes_at_first_write),
                seen_first: false,
            };
            let peak = AtomicUsize::new(0);
            let summary = run_streaming_with(
                vec![Arc::new(FirstTargetFastProber {
                    probes_done: Arc::clone(&probes_done),
                })],
                targets,
                Box::new(sink),
                8,
                &scan_metadata,
                &peak,
            )
            .await
            .expect("streaming summary");

            assert_eq!(summary.records_emitted, N as usize);
            let observed = probes_at_first_write.load(Ordering::SeqCst);
            assert!(
                observed < N as usize,
                "the first record ({observed} probes complete) must be written before the scan of \
                 all {N} targets finishes; a buffer-then-emit pipeline would write it only at the end"
            );
        }

        struct PortBudgetProber {
            ports: Vec<u16>,
            current: Arc<AtomicUsize>,
            peak: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl Prober for PortBudgetProber {
            fn kind(&self) -> ProbeKind {
                ProbeKind::TcpConnect
            }
            async fn probe(
                &self,
                target: &ResolvedTarget,
                ctx: &ProbeCtx,
            ) -> Result<ProbeOutcome, RastreoError> {
                let current = Arc::clone(&self.current);
                let peak = Arc::clone(&self.peak);
                crate::prober::ports::probe_ports(
                    &self.ports,
                    crate::prober::ports::MAX_PORTS_IN_FLIGHT,
                    ctx.port_budget.as_ref(),
                    move |_port| {
                        let current = Arc::clone(&current);
                        let peak = Arc::clone(&peak);
                        async move {
                            let in_flight = current.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(in_flight, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            current.fetch_sub(1, Ordering::SeqCst);
                        }
                    },
                )
                .await;
                Ok(ProbeOutcome {
                    lldp: None,
                    gnmi_endpoint: None,
                    kind: ProbeKind::TcpConnect,
                    target_ip: target.ip,
                    timestamp: SystemTime::UNIX_EPOCH,
                    reachable: false,
                    signals: Vec::new(),
                    fault: None,
                })
            }
        }

        // The guard: the global budget must cap total in-flight port ops at the concurrency cap, not
        // cap * ports. Driven through the real scheduler so the ctx-cloned Arc<Semaphore> is what
        // bounds every target's fan-out. Delete the acquire in `probe_ports` and the peak jumps to
        // CAP * PORTS, tripping the `<= CAP` assertion.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn global_port_budget_bounds_in_flight_ops_across_targets_and_ports() {
            const TARGETS: usize = 8;
            const PORTS: u16 = 16;
            const CAP: usize = 4;

            let current = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let probers: Vec<Arc<dyn Prober>> = vec![Arc::new(PortBudgetProber {
                ports: (1..=PORTS).collect(),
                current: Arc::clone(&current),
                peak: Arc::clone(&peak),
            })];

            let budget = Arc::new(Semaphore::new(CAP));
            let ctx = ProbeCtx::new(Duration::from_millis(500), 0)
                .with_port_budget(Some(Arc::clone(&budget)));
            let scheduler = BoundedScheduler::new(CAP);
            let (tx, mut rx) = mpsc::channel::<TargetScan>(CAP);
            let scan = scheduler.run_scan(
                probers,
                Box::new(resolved_many(TARGETS).into_iter()),
                ctx,
                watch::channel(false).1,
                tx,
            );
            tokio::pin!(scan);
            let mut done = false;
            loop {
                tokio::select! {
                    biased;
                    _ = &mut scan, if !done => { done = true; }
                    maybe = rx.recv() => {
                        if maybe.is_none() {
                            break;
                        }
                    }
                }
            }

            let observed = peak.load(Ordering::SeqCst);
            assert!(
                observed <= CAP,
                "global in-flight port ops {observed} must stay within the concurrency cap {CAP}, \
                 never cap * ports ({})",
                CAP * PORTS as usize
            );
            assert_eq!(
                observed, CAP,
                "with {TARGETS} targets * {PORTS} ports the shared budget should saturate to {CAP}"
            );
        }
    }

    struct FixedIpsResolver {
        ips: Vec<IpAddr>,
    }

    #[async_trait::async_trait]
    impl Resolver for FixedIpsResolver {
        async fn resolve(
            &self,
            target: &Target,
        ) -> Result<Vec<crate::model::ResolvedTarget>, RastreoError> {
            let now = std::time::SystemTime::now();
            Ok(self
                .ips
                .iter()
                .map(|&ip| crate::model::ResolvedTarget {
                    ip,
                    original: target.clone(),
                    resolved_at: now,
                })
                .collect())
        }
    }

    // Loads and stashes the on-disk checkpoint after each write, so a completing scan's periodic
    // checkpoints stay observable even though the final one is deleted.
    struct CheckpointObservingSink {
        delegate: crate::sink::MemorySink,
        checkpoint_path: std::path::PathBuf,
        observed: Arc<std::sync::Mutex<Vec<crate::checkpoint::Checkpoint>>>,
    }

    impl CheckpointObservingSink {
        fn capture(&self) {
            if let Ok(cp) = crate::checkpoint::Checkpoint::load(&self.checkpoint_path) {
                self.observed.lock().expect("lock").push(cp);
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::sink::Sink for CheckpointObservingSink {
        async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
            self.delegate.write(data).await?;
            self.capture();
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            self.delegate.flush().await
        }
        fn last_write_delivered(&self) -> bool {
            self.delegate.last_write_delivered()
        }
        fn kind(&self) -> SinkType {
            SinkType::Memory
        }
    }

    fn dns_scenario(port: u16, max_concurrent: u32, timeout_ms: u64) -> DiscoverScenarioConfig {
        DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(timeout_ms),
                max_concurrent: Some(max_concurrent),
                sink: Some(crate::sink::SinkConfig::Memory),
                ..Default::default()
            },
            targets: vec![Target::DnsName("hosts.lab".to_string())],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        }
    }

    #[tokio::test]
    async fn checkpointing_scan_writes_advancing_checkpoints_and_deletes_on_completion() {
        let port = open_loopback_port().await;
        let scenario = dns_scenario(port, 2, 500);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");

        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Box<dyn Sink> = Box::new(CheckpointObservingSink {
            delegate: mem,
            checkpoint_path: path.clone(),
            observed: Arc::clone(&observed),
        });

        let resolver: Arc<dyn Resolver> = Arc::new(FixedIpsResolver {
            ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST); 12],
        });
        let (_tx, rx) = watch::channel(false);
        let config = CheckpointConfig {
            path: path.clone(),
            interval: 5,
            resume: false,
        };

        let summary = run_discovery_core(&scenario, resolver, sink, rx, None, Some(config), None)
            .await
            .expect("checkpointing run");

        assert_eq!(
            summary.records_emitted, 12,
            "all 12 loopback probes reachable"
        );
        assert!(!summary.cancelled);
        assert!(!path.exists(), "a completed scan deletes its checkpoint");

        let observed = observed.lock().expect("lock");
        assert!(
            !observed.is_empty(),
            "periodic checkpoints must have been written mid-scan"
        );

        let indices: Vec<usize> = observed.iter().map(|c| c.highest_flushed_index).collect();
        assert!(
            indices.windows(2).all(|w| w[0] <= w[1]),
            "highest_flushed_index never regresses: {indices:?}"
        );
        assert_eq!(
            *indices.iter().max().expect("some observed"),
            9,
            "last boundary at next_expected=10 records K=9"
        );
        assert!(
            indices.contains(&4),
            "first boundary at next_expected=5 records K=4"
        );

        let expected_fingerprint = crate::checkpoint::resume_fingerprint(&scenario);
        let lines = handle.ndjson_lines();
        let record: DeviceRecord = serde_json::from_str(&lines[0]).expect("parse record");
        let scan_id = record.scan_metadata.scan_id.clone();
        for cp in observed.iter() {
            assert_eq!(
                cp.scan_id, scan_id,
                "checkpoint scan_id matches emitted records"
            );
            assert_eq!(cp.resume_fingerprint, expected_fingerprint);
            assert_eq!(cp.dns_pins.len(), 1);
            assert_eq!(cp.dns_pins[0].0, Target::DnsName("hosts.lab".to_string()));
            assert_eq!(cp.dns_pins[0].1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST); 12]);
        }
    }

    #[tokio::test]
    async fn cancelled_checkpointing_scan_leaves_a_final_checkpoint() {
        let port = open_loopback_port().await;
        let scenario = dns_scenario(port, 4, 400);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");

        let sink: Box<dyn Sink> = Box::new(crate::sink::MemorySink::new());
        // Loopback completes instantly; the three TEST-NET-2 addresses stay in flight past the 50ms
        // cancel, so the scan is still running when it is cancelled — a partial, resumable prefix.
        let resolver: Arc<dyn Resolver> = Arc::new(FixedIpsResolver {
            ips: vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3)),
            ],
        });

        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = tx.send(true);
        });

        let config = CheckpointConfig {
            path: path.clone(),
            interval: 1000,
            resume: false,
        };
        let summary = run_discovery_core(&scenario, resolver, sink, rx, None, Some(config), None)
            .await
            .expect("cancelled run returns a summary");

        assert!(summary.cancelled, "cancel signaled mid-scan");
        assert!(
            summary.records_emitted >= 1,
            "the reachable loopback target emitted a record"
        );
        assert!(
            path.exists(),
            "a cancelled scan leaves a final checkpoint to resume from"
        );
        let cp = crate::checkpoint::Checkpoint::load(&path).expect("load final checkpoint");
        assert!(
            cp.highest_flushed_index < summary.targets_resolved,
            "the final checkpoint records a partial prefix, not the whole scan"
        );
        assert_eq!(cp.dns_pins.len(), 1);
        assert_eq!(cp.dns_pins[0].1.len(), 4);
        assert_eq!(
            cp.resume_fingerprint,
            crate::checkpoint::resume_fingerprint(&scenario)
        );
    }

    #[tokio::test]
    async fn checkpoint_entry_refuses_ineligible_scenario_before_probing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                fuser: Some(FuserConfig::Identity {
                    identity_hints: crate::fuser::IdentityHints::default(),
                    inner: Box::new(FuserConfig::Direct {
                        include_unreachable: None,
                        confidence_baseline: None,
                        confidence_per_signal: None,
                    }),
                }),
                sink: Some(crate::sink::SinkConfig::File {
                    path: dir.path().join("out.ndjson"),
                }),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![9] }],
        };

        let (progress_tx, _progress_rx) = watch::channel(DiscoveryProgress::default());
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let config = CheckpointConfig {
            path: path.clone(),
            interval: 5,
            resume: false,
        };

        let err = run_discovery(
            RunOptions::new(&scenario)
                .cancel(cancel_rx)
                .progress(progress_tx)
                .checkpoint(config),
        )
        .await
        .expect_err("an identity-fuser scenario is refused pre-flight");
        assert!(matches!(
            err,
            RastreoError::Resume(crate::error::ResumeError::IdentityFuserNotResumable)
        ));
        assert!(!path.exists(), "a refused scan writes no checkpoint");
    }

    // A resumed scan restores the crashed scan's identity, so records emitted after resume carry the
    // same scan_id/initiated_at the checkpoint recorded — downstream groups the logical scan by it.
    const RESUMED_SCAN_ID: &str = "01JRESUME0000000000000000A";
    const RESUMED_INITIATED_SECS: u64 = 1_700_000_000;

    fn loopback_ips(n: usize) -> Vec<IpAddr> {
        (1..=n as u8)
            .map(|i| IpAddr::V4(Ipv4Addr::new(127, 0, 0, i)))
            .collect()
    }

    // Distinct dark loopback IPs behind one DNS target; include_unreachable emits one record per IP so
    // every target is identifiable by its mgmt_ip in the sink.
    fn resume_dns_scenario(out: &std::path::Path) -> DiscoverScenarioConfig {
        use crate::prober::UdpProtocol;
        DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(150),
                max_concurrent: Some(8),
                fuser: Some(FuserConfig::Direct {
                    include_unreachable: Some(true),
                    confidence_baseline: None,
                    confidence_per_signal: None,
                }),
                sink: Some(SinkConfig::File {
                    path: out.to_path_buf(),
                }),
                ..Default::default()
            },
            targets: vec![Target::DnsName("hosts.lab".to_string())],
            probers: vec![ProberConfig::Udp {
                ports: vec![1],
                protocol: UdpProtocol::Ntp,
            }],
        }
    }

    fn resume_checkpoint(
        scenario: &DiscoverScenarioConfig,
        all_ips: &[IpAddr],
        highest_flushed_index: usize,
    ) -> Checkpoint {
        Checkpoint {
            checkpoint_version: crate::checkpoint::CHECKPOINT_VERSION,
            scan_id: RESUMED_SCAN_ID.to_string(),
            initiated_at: std::time::UNIX_EPOCH + Duration::from_secs(RESUMED_INITIATED_SECS),
            resume_fingerprint: resume_fingerprint(scenario),
            source_config_hash: crate::model::scan::hash_scenario(scenario),
            dns_pins: vec![(Target::DnsName("hosts.lab".to_string()), all_ips.to_vec())],
            highest_flushed_index,
        }
    }

    fn records_from(path: &std::path::Path) -> Vec<DeviceRecord> {
        std::fs::read(path)
            .expect("read output")
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice(l).expect("parse record"))
            .collect()
    }

    #[tokio::test]
    async fn resume_skips_done_prefix_reprobes_boundary_and_preserves_scan_id() {
        const N: usize = 8;
        const K: usize = 3;
        let all_ips = loopback_ips(N);
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("out.ndjson");
        let cp_path = dir.path().join("scan.checkpoint");
        let scenario = resume_dns_scenario(&out);

        // Seed the pre-crash durable prefix: probe just targets 0..=K to the output file. from_pinned
        // never re-resolves "hosts.lab" (unresolvable by the system resolver), so the resume below
        // succeeding at all proves it replayed the pinned addresses instead.
        let seed_resolver: Arc<dyn Resolver> = Arc::new(FixedIpsResolver {
            ips: all_ips[..=K].to_vec(),
        });
        let seed_sink = create_sink(&SinkConfig::File { path: out.clone() })
            .await
            .expect("seed sink");
        run_discovery(
            RunOptions::new(&scenario)
                .resolver(seed_resolver)
                .sink(seed_sink),
        )
        .await
        .expect("seed run");
        assert_eq!(records_from(&out).len(), K + 1, "seed wrote targets 0..=K");

        resume_checkpoint(&scenario, &all_ips, K)
            .write(&cp_path)
            .expect("seed checkpoint");

        let (progress_tx, _progress_rx) = watch::channel(DiscoveryProgress::default());
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let config = CheckpointConfig {
            path: cp_path.clone(),
            interval: 1000,
            resume: true,
        };
        let summary = run_discovery(
            RunOptions::new(&scenario)
                .cancel(cancel_rx)
                .progress(progress_tx)
                .checkpoint(config),
        )
        .await
        .expect("resume run");

        assert_eq!(
            summary.records_emitted,
            N - K,
            "the resume re-probes the boundary K plus every later target"
        );
        assert!(
            !cp_path.exists(),
            "a completed resume deletes the checkpoint"
        );

        let records = records_from(&out);
        assert_eq!(
            records.len(),
            N + 1,
            "seed prefix plus the resumed remainder"
        );

        let mut counts: BTreeMap<IpAddr, usize> = BTreeMap::new();
        for r in &records {
            *counts.entry(r.mgmt_ip.expect("mgmt_ip")).or_default() += 1;
        }
        for ip in &all_ips {
            assert!(counts.contains_key(ip), "no gap: {ip} must be covered");
        }
        let dupes: Vec<(&IpAddr, &usize)> = counts.iter().filter(|(_, c)| **c > 1).collect();
        assert_eq!(dupes.len(), 1, "exactly one boundary duplicate: {counts:?}");
        assert_eq!(
            *dupes[0].0, all_ips[K],
            "the duplicate is the boundary target K"
        );
        assert_eq!(*dupes[0].1, 2);

        let resumed: Vec<&DeviceRecord> = records
            .iter()
            .filter(|r| r.scan_metadata.scan_id == RESUMED_SCAN_ID)
            .collect();
        assert_eq!(
            resumed.len(),
            N - K,
            "resumed records carry the checkpoint's scan_id"
        );
        let want_initiated = std::time::UNIX_EPOCH + Duration::from_secs(RESUMED_INITIATED_SECS);
        assert!(resumed
            .iter()
            .all(|r| r.scan_metadata.initiated_at == want_initiated));
        let resumed_ips: std::collections::BTreeSet<IpAddr> =
            resumed.iter().map(|r| r.mgmt_ip.expect("ip")).collect();
        let expected_ips: std::collections::BTreeSet<IpAddr> =
            all_ips[K..].iter().copied().collect();
        assert_eq!(
            resumed_ips, expected_ips,
            "the resume covers exactly the boundary target and every later one"
        );
    }

    #[tokio::test]
    async fn resumed_run_records_global_checkpoint_indices_and_progress() {
        const N: usize = 8;
        const K: usize = 3;
        let all_ips = loopback_ips(N);
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("ignored.ndjson");
        let cp_path = dir.path().join("scan.checkpoint");
        let scenario = resume_dns_scenario(&out);
        let checkpoint = resume_checkpoint(&scenario, &all_ips, K);
        checkpoint.write(&cp_path).expect("seed checkpoint");

        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Box<dyn Sink> = Box::new(CheckpointObservingSink {
            delegate: crate::sink::MemorySink::new(),
            checkpoint_path: cp_path.clone(),
            observed: Arc::clone(&observed),
        });
        // The resume rebuilds the plan from the pins, so the resolver is never consulted.
        let resolver: Arc<dyn Resolver> = Arc::new(FixedIpsResolver {
            ips: all_ips.clone(),
        });
        let (progress_tx, progress_rx) = watch::channel(DiscoveryProgress::default());
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let config = CheckpointConfig {
            path: cp_path.clone(),
            interval: 1,
            resume: false,
        };
        let summary = run_discovery_core(
            &scenario,
            resolver,
            sink,
            cancel_rx,
            Some(progress_tx),
            Some(config),
            Some(checkpoint),
        )
        .await
        .expect("resumed run");

        assert_eq!(summary.records_emitted, N - K);

        let indices: Vec<usize> = observed
            .lock()
            .expect("lock")
            .iter()
            .map(|c| c.highest_flushed_index)
            .collect();
        assert!(!indices.is_empty(), "the continued run wrote checkpoints");
        assert!(
            indices.iter().all(|&i| i >= K),
            "global indices never drop below the resume base K={K}: {indices:?}"
        );
        assert!(
            indices.windows(2).all(|w| w[0] <= w[1]),
            "highest_flushed_index never regresses: {indices:?}"
        );
        assert!(
            indices.iter().any(|&i| i > K),
            "the continued checkpoint advances the global index past K: {indices:?}"
        );
        assert!(
            !cp_path.exists(),
            "a completed resume deletes the checkpoint"
        );

        let final_progress = progress_rx.borrow().clone();
        assert_eq!(
            final_progress.targets_total, N,
            "denominator is the full target count"
        );
        assert_eq!(
            final_progress.targets_completed, N,
            "progress reports the global position K/N .. N, never 0/(N-K)"
        );
    }

    #[tokio::test]
    async fn resume_entry_refuses_when_no_checkpoint_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("out.ndjson");
        let cp_path = dir.path().join("absent.checkpoint");
        let scenario = resume_dns_scenario(&out);

        let (progress_tx, _progress_rx) = watch::channel(DiscoveryProgress::default());
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let config = CheckpointConfig {
            path: cp_path.clone(),
            interval: 5,
            resume: true,
        };
        let err = run_discovery(
            RunOptions::new(&scenario)
                .cancel(cancel_rx)
                .progress(progress_tx)
                .checkpoint(config),
        )
        .await
        .expect_err("--resume with no checkpoint is refused");
        assert!(matches!(
            err,
            RastreoError::Resume(crate::error::ResumeError::NoCheckpointToResume { .. })
        ));
    }

    mod empty_encoding_contract {
        use super::*;
        use crate::model::{GnmiEndpoint, Signal, Transport};
        use crate::sink::RecordKind;
        use std::sync::Mutex as StdMutex;
        use std::time::SystemTime;

        struct WritesNothingEncoder;

        impl Encoder for WritesNothingEncoder {
            fn encode_record(&self, _: &DeviceRecord, _: &mut Vec<u8>) -> Result<(), RastreoError> {
                Ok(())
            }
            fn encode_link(
                &self,
                _: &crate::model::LinkRecord,
                _: &mut Vec<u8>,
            ) -> Result<(), RastreoError> {
                Ok(())
            }
            fn encode_profile(
                &self,
                _: &crate::model::CollectionProfileRecord,
                _: &mut Vec<u8>,
            ) -> Result<(), RastreoError> {
                Ok(())
            }
        }

        #[derive(Default)]
        struct WriteLog {
            writes: Arc<StdMutex<Vec<(RecordKind, usize)>>>,
        }

        impl WriteLog {
            fn entries(&self) -> Vec<(RecordKind, usize)> {
                self.writes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
            }
        }

        struct LoggingSink {
            writes: Arc<StdMutex<Vec<(RecordKind, usize)>>>,
        }

        #[async_trait::async_trait]
        impl Sink for LoggingSink {
            async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
                self.writes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((RecordKind::Device, data.len()));
                Ok(())
            }
            async fn write_kind(
                &mut self,
                kind: RecordKind,
                data: &[u8],
            ) -> Result<(), RastreoError> {
                self.writes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((kind, data.len()));
                Ok(())
            }
            async fn flush(&mut self) -> Result<(), RastreoError> {
                Ok(())
            }
            fn last_write_delivered(&self) -> bool {
                true
            }
            fn kind(&self) -> SinkType {
                SinkType::Memory
            }
        }

        struct GnmiProber;

        #[async_trait::async_trait]
        impl Prober for GnmiProber {
            fn kind(&self) -> ProbeKind {
                ProbeKind::Gnmi
            }
            async fn probe(
                &self,
                target: &ResolvedTarget,
                _ctx: &ProbeCtx,
            ) -> Result<ProbeOutcome, RastreoError> {
                Ok(ProbeOutcome {
                    kind: ProbeKind::Gnmi,
                    target_ip: target.ip,
                    timestamp: SystemTime::UNIX_EPOCH,
                    reachable: true,
                    signals: vec![
                        Signal::GnmiVersion("0.10.0".into()),
                        Signal::GnmiSupportedEncoding("JSON_IETF".into()),
                    ],
                    fault: None,
                    lldp: None,
                    gnmi_endpoint: Some(GnmiEndpoint {
                        port: 57400,
                        transport: Transport::Tls,
                        advertised_encodings: vec!["JSON_IETF".into()],
                    }),
                })
            }
        }

        fn all_kinds_probers() -> Vec<Arc<dyn Prober>> {
            vec![
                Arc::new(MutualLldpProber {
                    cx: "aaaaaaaaaaaa",
                    cy: "bbbbbbbbbbbb",
                }),
                Arc::new(GnmiProber),
            ]
        }

        fn two_targets() -> Vec<ResolvedTarget> {
            (1u8..=2)
                .map(|i| {
                    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
                    ResolvedTarget {
                        ip,
                        original: Target::Ip(ip),
                        resolved_at: SystemTime::UNIX_EPOCH,
                    }
                })
                .collect()
        }

        async fn run_streaming_with_encoder(
            encoder: &dyn Encoder,
            log: &WriteLog,
        ) -> DiscoverySummary {
            let scan_metadata = Arc::new(ScanMetadata::default());
            let mut fuser = create_fuser(&FuserConfig::Direct {
                include_unreachable: None,
                confidence_baseline: None,
                confidence_per_signal: None,
            })
            .expect("fuser");
            let classifier = create_classifier(&ClassifierConfig::Noop).expect("classifier");
            let mut sink: Box<dyn Sink> = Box::new(LoggingSink {
                writes: Arc::clone(&log.writes),
            });
            let scheduler = BoundedScheduler::new(8);
            let peak = AtomicUsize::new(0);
            let scan_span = tracing::info_span!("scan");
            stream_discovery(
                &scheduler,
                all_kinds_probers(),
                Box::new(two_targets().into_iter()),
                ProbeCtx::new(Duration::from_millis(100), 0),
                watch::channel(false).1,
                fuser.as_mut(),
                classifier.as_ref(),
                encoder,
                sink.as_mut(),
                &scan_metadata,
                2,
                Instant::now(),
                0,
                &peak,
                &scan_span,
                None,
                None,
            )
            .await
            .expect("streaming summary")
        }

        async fn run_batch_with_encoder(encoder: &dyn Encoder, log: &WriteLog) -> DiscoverySummary {
            let scan_metadata = Arc::new(ScanMetadata::default());
            let probers = all_kinds_probers();
            let prober_kinds: Vec<ProbeKind> = probers.iter().map(|p| p.kind()).collect();
            let mut fuser = create_fuser(&FuserConfig::Direct {
                include_unreachable: None,
                confidence_baseline: None,
                confidence_per_signal: None,
            })
            .expect("fuser");
            let classifier = create_classifier(&ClassifierConfig::Noop).expect("classifier");
            let mut sink: Box<dyn Sink> = Box::new(LoggingSink {
                writes: Arc::clone(&log.writes),
            });
            let scheduler = BoundedScheduler::new(8);
            let (scans, cancelled) = collect_scans_sorted(
                &scheduler,
                probers,
                two_targets(),
                ProbeCtx::new(Duration::from_millis(100), 0),
                watch::channel(false).1,
            )
            .await;
            let acc = accumulate_scans(scans, &prober_kinds, cancelled);
            finish_discovery_ref(
                acc,
                fuser.as_mut(),
                classifier.as_ref(),
                encoder,
                sink.as_mut(),
                &scan_metadata,
                2,
                Instant::now(),
            )
            .await
            .expect("batch summary")
        }

        #[tokio::test]
        async fn the_probers_exercise_every_record_kind() {
            // Without this, "nothing was written" below could just mean nothing was reachable.
            let encoder = create_encoder(&EncoderConfig::Ndjson).expect("encoder");
            let log = WriteLog::default();
            let summary = run_streaming_with_encoder(encoder.as_ref(), &log).await;
            assert_eq!(summary.records_emitted, 2);
            assert_eq!(summary.links_emitted, 1);
            assert_eq!(summary.profiles_emitted, 2);
            let kinds: Vec<RecordKind> = log.entries().into_iter().map(|(k, _)| k).collect();
            assert!(kinds.contains(&RecordKind::Device));
            assert!(kinds.contains(&RecordKind::Link));
            assert!(kinds.contains(&RecordKind::CollectionProfile));
            assert!(log.entries().iter().all(|(_, len)| *len > 0));
        }

        #[tokio::test]
        async fn streaming_skips_the_write_when_the_encoder_renders_nothing() {
            let log = WriteLog::default();
            let summary = run_streaming_with_encoder(&WritesNothingEncoder, &log).await;
            assert_eq!(log.entries(), Vec::new(), "no empty message may be sent");
            assert_eq!(summary.records_emitted, 0);
            assert_eq!(summary.links_emitted, 0);
            assert_eq!(summary.profiles_emitted, 0);
        }

        #[tokio::test]
        async fn the_batch_reference_skips_the_write_when_the_encoder_renders_nothing() {
            let log = WriteLog::default();
            let summary = run_batch_with_encoder(&WritesNothingEncoder, &log).await;
            assert_eq!(log.entries(), Vec::new(), "no empty message may be sent");
            assert_eq!(summary.records_emitted, 0);
            assert_eq!(summary.links_emitted, 0);
            assert_eq!(summary.profiles_emitted, 0);
        }

        #[tokio::test]
        async fn the_table_encoder_writes_device_rows_and_no_second_stream() {
            let encoder = create_encoder(&EncoderConfig::Table { width: 100 }).expect("encoder");
            let log = WriteLog::default();
            let summary = run_streaming_with_encoder(encoder.as_ref(), &log).await;
            assert_eq!(summary.records_emitted, 2);
            assert_eq!(
                summary.links_emitted, 0,
                "links do not render as table rows"
            );
            assert_eq!(
                summary.profiles_emitted, 0,
                "profiles do not render as table rows"
            );
            let kinds: Vec<RecordKind> = log.entries().into_iter().map(|(k, _)| k).collect();
            assert_eq!(kinds, vec![RecordKind::Device, RecordKind::Device]);
        }
    }

    mod encoder_sink_compatibility {
        use super::*;
        use crate::sink::{MemorySink, TeeChild, TeeSink};

        fn table_scenario(sink: Option<SinkConfig>) -> DiscoverScenarioConfig {
            table_scenario_on_port(sink, 9)
        }

        fn table_scenario_on_port(sink: Option<SinkConfig>, port: u16) -> DiscoverScenarioConfig {
            let base = BaseProbeConfig {
                encoder: Some(EncoderConfig::Table { width: 100 }),
                sink,
                ..BaseProbeConfig::default()
            };
            DiscoverScenarioConfig {
                base,
                targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
                probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
            }
        }

        struct StructuredOnlySink;

        #[async_trait::async_trait]
        impl Sink for StructuredOnlySink {
            async fn write(&mut self, _: &[u8]) -> Result<(), RastreoError> {
                Ok(())
            }
            async fn flush(&mut self) -> Result<(), RastreoError> {
                Ok(())
            }
            fn last_write_delivered(&self) -> bool {
                true
            }
            // A local kind under a structured answer, so the guard must read the sink's answer, not its kind.
            fn kind(&self) -> SinkType {
                SinkType::Memory
            }
            async fn requires_structured_records(&self) -> bool {
                true
            }
        }

        #[tokio::test]
        async fn an_injected_structured_sink_rejects_the_table_encoder() {
            let scenario = table_scenario(None);
            let err = run_discovery(RunOptions::new(&scenario).sink(Box::new(StructuredOnlySink)))
                .await
                .expect_err("a sink injected past the config must still be checked");
            match err {
                RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                    assert!(msg.contains("table encoder"), "msg was: {msg}");
                }
                other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn an_injected_fan_out_sink_with_a_structured_child_rejects_the_table_encoder() {
            let scenario = table_scenario(None);
            let tee = TeeSink::new(vec![
                TeeChild::Owned(Box::new(MemorySink::new())),
                TeeChild::Owned(Box::new(StructuredOnlySink)),
            ]);
            let err = run_discovery(RunOptions::new(&scenario).sink(Box::new(tee)))
                .await
                .expect_err("a broker among the children makes the whole fan-out structured");
            match err {
                RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                    assert!(msg.contains("table encoder"), "msg was: {msg}");
                }
                other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn an_injected_plain_sink_receives_the_rendered_table() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let port = listener.local_addr().expect("local_addr").port();
            let scenario = table_scenario_on_port(None, port);
            let sink = MemorySink::new();
            let handle = sink.handle();
            run_discovery(RunOptions::new(&scenario).sink(Box::new(sink)))
                .await
                .expect("a plain sink carries table output");
            let lines = handle.ndjson_lines();
            assert!(
                lines.first().is_some_and(|l| l.starts_with("ADDRESS")),
                "rendered: {lines:?}"
            );
            assert!(
                lines.iter().any(|l| l.starts_with("127.0.0.1")),
                "rendered: {lines:?}"
            );
        }

        #[cfg(feature = "kafka")]
        #[tokio::test]
        async fn a_kafka_sink_config_rejects_the_table_encoder_before_dialling_the_broker() {
            // 127.0.0.1:1 is a black hole: reaching create_sink at all yields a connect error.
            let scenario = table_scenario(Some(SinkConfig::Kafka {
                brokers: vec!["127.0.0.1:1".into()],
                topic: "rastreo.devices".into(),
                links_topic: None,
                profiles_topic: None,
                flush_mode: crate::sink::KafkaFlushMode::default(),
                dead_letter: None,
                tls: None,
                sasl: None,
                retry: crate::sink::SinkRetry::default(),
            }));
            let started = Instant::now();
            let err = run_discovery(RunOptions::new(&scenario))
                .await
                .expect_err("table into kafka must be rejected");
            match err {
                RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                    assert!(msg.contains("table encoder"), "msg was: {msg}");
                }
                other => panic!("expected the offline ConfigError, got {other:?}"),
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the rejection must precede the broker connect"
            );
        }

        #[tokio::test]
        async fn a_memory_sink_config_accepts_the_table_encoder() {
            let scenario = table_scenario(Some(SinkConfig::Memory));
            run_discovery(RunOptions::new(&scenario))
                .await
                .expect("the memory sink carries table output");
        }
    }

    mod close_on_every_exit {
        use super::*;

        use std::time::SystemTime;

        use crate::classifier::NoopClassifier;
        use crate::model::{
            Confidence, IdentityKey, Signal, CURRENT_SCHEMA_ID, CURRENT_SCHEMA_VERSION,
        };

        const INGEST_REFUSED: &str = "ingest refused";
        const FINISH_REFUSED: &str = "finish refused";
        const CLASSIFY_REFUSED: &str = "classify refused";
        const WRITE_REFUSED: &str = "write refused";

        fn refusal(detail: &str) -> RastreoError {
            ConfigError::invalid(detail).into()
        }

        fn one_record() -> DeviceRecord {
            DeviceRecord {
                identity_key: IdentityKey::new("ip:10.0.0.1").expect("identity"),
                mgmt_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                mac: None,
                manufacturer: None,
                model: None,
                product_family: None,
                platform: None,
                os_version: None,
                ssh_version: None,
                http_server: None,
                http_version: None,
                role: None,
                confidence: Confidence::new(0.5).expect("confidence"),
                last_seen: SystemTime::UNIX_EPOCH,
                signals: Vec::new(),
                probe_kinds: Vec::new(),
                schema_version: CURRENT_SCHEMA_VERSION.to_string(),
                schema_id: CURRENT_SCHEMA_ID.to_string(),
                alt_ips: Vec::new(),
                possible_alias_of: None,
                scan_metadata: Arc::new(ScanMetadata::default()),
            }
        }

        struct IngestFailsFuser;

        impl Fuser for IngestFailsFuser {
            fn ingest(
                &mut self,
                _outcomes: Vec<ProbeOutcome>,
            ) -> Result<Vec<DeviceRecord>, RastreoError> {
                Err(refusal(INGEST_REFUSED))
            }
            fn finish(&mut self) -> Result<Vec<DeviceRecord>, RastreoError> {
                Ok(Vec::new())
            }
        }

        struct FinishFailsFuser;

        impl Fuser for FinishFailsFuser {
            fn ingest(
                &mut self,
                _outcomes: Vec<ProbeOutcome>,
            ) -> Result<Vec<DeviceRecord>, RastreoError> {
                Ok(Vec::new())
            }
            fn finish(&mut self) -> Result<Vec<DeviceRecord>, RastreoError> {
                Err(refusal(FINISH_REFUSED))
            }
        }

        // Emits per ingest like DirectFuser, so a classifier runs while the scan is draining.
        struct PerIngestFuser;

        impl Fuser for PerIngestFuser {
            fn ingest(
                &mut self,
                _outcomes: Vec<ProbeOutcome>,
            ) -> Result<Vec<DeviceRecord>, RastreoError> {
                Ok(vec![one_record()])
            }
            fn finish(&mut self) -> Result<Vec<DeviceRecord>, RastreoError> {
                Ok(Vec::new())
            }
        }

        struct EmitsThenFinishFailsFuser;

        impl Fuser for EmitsThenFinishFailsFuser {
            fn ingest(
                &mut self,
                _outcomes: Vec<ProbeOutcome>,
            ) -> Result<Vec<DeviceRecord>, RastreoError> {
                Ok(vec![one_record()])
            }
            fn finish(&mut self) -> Result<Vec<DeviceRecord>, RastreoError> {
                Err(refusal(FINISH_REFUSED))
            }
        }

        // Buffers until finish like IdentityFuser, so a classifier runs in the finish block.
        struct OnFinishFuser;

        impl Fuser for OnFinishFuser {
            fn ingest(
                &mut self,
                _outcomes: Vec<ProbeOutcome>,
            ) -> Result<Vec<DeviceRecord>, RastreoError> {
                Ok(Vec::new())
            }
            fn finish(&mut self) -> Result<Vec<DeviceRecord>, RastreoError> {
                Ok(vec![one_record()])
            }
        }

        struct FailingClassifier;

        impl Classifier for FailingClassifier {
            fn classify(&self, _record: &mut DeviceRecord) -> Result<(), RastreoError> {
                Err(refusal(CLASSIFY_REFUSED))
            }
        }

        struct ReachableProber;

        #[async_trait::async_trait]
        impl Prober for ReachableProber {
            fn kind(&self) -> ProbeKind {
                ProbeKind::TcpConnect
            }
            async fn probe(
                &self,
                target: &ResolvedTarget,
                _ctx: &ProbeCtx,
            ) -> Result<ProbeOutcome, RastreoError> {
                Ok(ProbeOutcome {
                    lldp: None,
                    gnmi_endpoint: None,
                    kind: ProbeKind::TcpConnect,
                    target_ip: target.ip,
                    timestamp: SystemTime::UNIX_EPOCH,
                    reachable: true,
                    signals: vec![Signal::OpenPort(22)],
                    fault: None,
                })
            }
        }

        #[derive(Clone, Copy, PartialEq)]
        enum Writes {
            Succeed,
            Fail,
        }

        struct CloseCountingSink {
            closes: Arc<AtomicUsize>,
            writes: Writes,
        }

        #[async_trait::async_trait]
        impl Sink for CloseCountingSink {
            async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
                if self.writes == Writes::Fail {
                    return Err(RastreoError::Sink(crate::sink::SinkError::new(
                        SinkErrorClass::WriteFailure,
                        std::io::Error::other(WRITE_REFUSED),
                    )));
                }
                Ok(())
            }
            async fn flush(&mut self) -> Result<(), RastreoError> {
                Ok(())
            }
            async fn close(&mut self) -> Result<(), RastreoError> {
                self.closes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            fn last_write_delivered(&self) -> bool {
                true
            }
            fn kind(&self) -> SinkType {
                SinkType::Memory
            }
        }

        // Stands in for a probe that keeps hitting the network: it advances whenever the runtime polls it.
        struct SpinsOnSecondTargetProber {
            polls: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl Prober for SpinsOnSecondTargetProber {
            fn kind(&self) -> ProbeKind {
                ProbeKind::TcpConnect
            }
            async fn probe(
                &self,
                target: &ResolvedTarget,
                ctx: &ProbeCtx,
            ) -> Result<ProbeOutcome, RastreoError> {
                if target.ip == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)) {
                    loop {
                        self.polls.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                    }
                }
                ReachableProber.probe(target, ctx).await
            }
        }

        struct SlowClosingSink {
            polls: Arc<AtomicUsize>,
            polls_before_close: Arc<AtomicUsize>,
            polls_during_close: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl Sink for SlowClosingSink {
            async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
                Ok(())
            }
            async fn flush(&mut self) -> Result<(), RastreoError> {
                Ok(())
            }
            async fn close(&mut self) -> Result<(), RastreoError> {
                let before = self.polls.load(Ordering::SeqCst);
                self.polls_before_close.store(before, Ordering::SeqCst);
                for _ in 0..8 {
                    tokio::task::yield_now().await;
                }
                self.polls_during_close
                    .store(self.polls.load(Ordering::SeqCst) - before, Ordering::SeqCst);
                Ok(())
            }
            fn last_write_delivered(&self) -> bool {
                true
            }
            fn kind(&self) -> SinkType {
                SinkType::Memory
            }
        }

        async fn stream_into(
            sink: &mut dyn Sink,
            probers: Vec<Arc<dyn Prober>>,
            fuser: &mut dyn Fuser,
            classifier: &dyn Classifier,
            checkpoint: Option<CheckpointWriter>,
        ) -> Result<DiscoverySummary, RastreoError> {
            let encoder = create_encoder(&EncoderConfig::Ndjson).expect("encoder");
            let scheduler = BoundedScheduler::new(4);
            let targets: Vec<ResolvedTarget> = (1..=2u8)
                .map(|last| {
                    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, last));
                    ResolvedTarget {
                        ip,
                        original: Target::Ip(ip),
                        resolved_at: SystemTime::UNIX_EPOCH,
                    }
                })
                .collect();
            let targets_resolved = targets.len();
            let scan_metadata = Arc::new(ScanMetadata::default());
            let peak = AtomicUsize::new(0);
            let scan_span = tracing::info_span!("scan");
            stream_discovery(
                &scheduler,
                probers,
                Box::new(targets.into_iter()),
                ProbeCtx::new(Duration::from_millis(100), 0),
                watch::channel(false).1,
                fuser,
                classifier,
                encoder.as_ref(),
                sink,
                &scan_metadata,
                targets_resolved,
                Instant::now(),
                0,
                &peak,
                &scan_span,
                None,
                checkpoint,
            )
            .await
        }

        async fn stream_with(
            fuser: &mut dyn Fuser,
            classifier: &dyn Classifier,
            checkpoint: Option<CheckpointWriter>,
            writes: Writes,
        ) -> (Result<DiscoverySummary, RastreoError>, usize) {
            let closes = Arc::new(AtomicUsize::new(0));
            let mut sink = CloseCountingSink {
                closes: Arc::clone(&closes),
                writes,
            };
            let result = stream_into(
                &mut sink,
                vec![Arc::new(ReachableProber)],
                fuser,
                classifier,
                checkpoint,
            )
            .await;
            (result, closes.load(Ordering::SeqCst))
        }

        async fn batch_with(
            fuser: &mut dyn Fuser,
            classifier: &dyn Classifier,
        ) -> (Result<DiscoverySummary, RastreoError>, usize) {
            let closes = Arc::new(AtomicUsize::new(0));
            let mut sink: Box<dyn Sink> = Box::new(CloseCountingSink {
                closes: Arc::clone(&closes),
                writes: Writes::Succeed,
            });
            let encoder = create_encoder(&EncoderConfig::Ndjson).expect("encoder");
            let scan_metadata = Arc::new(ScanMetadata::default());
            let acc = ScanAccumulation {
                all_outcomes: vec![ProbeOutcome {
                    lldp: None,
                    gnmi_endpoint: None,
                    kind: ProbeKind::TcpConnect,
                    target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    timestamp: SystemTime::UNIX_EPOCH,
                    reachable: true,
                    signals: vec![Signal::OpenPort(22)],
                    fault: None,
                }],
                ..Default::default()
            };
            let result = finish_discovery_ref(
                acc,
                fuser,
                classifier,
                encoder.as_ref(),
                sink.as_mut(),
                &scan_metadata,
                1,
                Instant::now(),
            )
            .await;
            (result, closes.load(Ordering::SeqCst))
        }

        fn refusal_detail(result: Result<DiscoverySummary, RastreoError>) -> String {
            result
                .expect_err("the fuser or classifier refusal must reach the caller")
                .to_string()
        }

        #[tokio::test]
        async fn a_clean_run_closes_the_sink_exactly_once() {
            let (result, closes) =
                stream_with(&mut PerIngestFuser, &NoopClassifier, None, Writes::Succeed).await;
            result.expect("a clean run summarises");
            assert_eq!(closes, 1);
        }

        #[tokio::test]
        async fn a_fuser_that_fails_on_ingest_still_closes_the_sink() {
            let (result, closes) = stream_with(
                &mut IngestFailsFuser,
                &NoopClassifier,
                None,
                Writes::Succeed,
            )
            .await;
            assert!(refusal_detail(result).contains(INGEST_REFUSED));
            assert_eq!(closes, 1);
        }

        #[tokio::test]
        async fn a_fuser_that_fails_on_finish_still_closes_the_sink() {
            let (result, closes) = stream_with(
                &mut FinishFailsFuser,
                &NoopClassifier,
                None,
                Writes::Succeed,
            )
            .await;
            assert!(refusal_detail(result).contains(FINISH_REFUSED));
            assert_eq!(closes, 1);
        }

        #[tokio::test]
        async fn a_classifier_that_fails_while_draining_still_closes_the_sink() {
            let (result, closes) = stream_with(
                &mut PerIngestFuser,
                &FailingClassifier,
                None,
                Writes::Succeed,
            )
            .await;
            assert!(refusal_detail(result).contains(CLASSIFY_REFUSED));
            assert_eq!(closes, 1);
        }

        #[tokio::test]
        async fn a_classifier_that_fails_in_the_finish_block_still_closes_the_sink() {
            let (result, closes) = stream_with(
                &mut OnFinishFuser,
                &FailingClassifier,
                None,
                Writes::Succeed,
            )
            .await;
            assert!(refusal_detail(result).contains(CLASSIFY_REFUSED));
            assert_eq!(closes, 1);
        }

        #[tokio::test]
        async fn a_finish_failure_outranks_a_sink_error_the_drain_already_captured() {
            let (result, closes) = stream_with(
                &mut EmitsThenFinishFailsFuser,
                &NoopClassifier,
                None,
                Writes::Fail,
            )
            .await;
            let detail = refusal_detail(result);
            assert!(detail.contains(FINISH_REFUSED), "{detail}");
            assert!(!detail.contains(WRITE_REFUSED), "{detail}");
            assert_eq!(closes, 1);
        }

        #[tokio::test]
        async fn the_batch_reference_closes_the_sink_when_the_fuser_refuses() {
            let (result, closes) = batch_with(&mut IngestFailsFuser, &NoopClassifier).await;
            assert!(refusal_detail(result).contains(INGEST_REFUSED));
            assert_eq!(closes, 1);
        }

        #[tokio::test]
        async fn the_batch_reference_closes_the_sink_when_the_classifier_refuses() {
            let (result, closes) = batch_with(&mut PerIngestFuser, &FailingClassifier).await;
            assert!(refusal_detail(result).contains(CLASSIFY_REFUSED));
            assert_eq!(closes, 1);
        }

        #[tokio::test]
        async fn a_fuser_failure_leaves_the_last_good_checkpoint_in_place() {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("scan.checkpoint");
            std::fs::write(&path, b"prior run").expect("seed the checkpoint");
            let writer = CheckpointWriter::new(
                CheckpointConfig {
                    path: path.clone(),
                    interval: 1_000,
                    resume: false,
                },
                &ScanMetadata::default(),
                "fingerprint".to_string(),
                Vec::new(),
            );

            let (result, closes) = stream_with(
                &mut IngestFailsFuser,
                &NoopClassifier,
                Some(writer),
                Writes::Succeed,
            )
            .await;

            assert!(refusal_detail(result).contains(INGEST_REFUSED));
            assert_eq!(closes, 1);
            assert!(path.exists());
        }

        #[tokio::test]
        async fn a_finish_failure_still_commits_the_records_the_drain_buffered() {
            let mut sink = BatchingSink::new();
            let handle = sink.handle();

            let result = stream_into(
                &mut sink,
                vec![Arc::new(ReachableProber)],
                &mut EmitsThenFinishFailsFuser,
                &NoopClassifier,
                None,
            )
            .await;

            assert!(refusal_detail(result).contains(FINISH_REFUSED));
            let committed = handle.committed.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(
                committed.len(),
                2,
                "close() must land the records the drain buffered before the fuser refused"
            );
        }

        #[tokio::test]
        async fn an_in_flight_probe_stops_before_the_sink_closes() {
            let polls = Arc::new(AtomicUsize::new(0));
            let polls_before_close = Arc::new(AtomicUsize::new(0));
            let polls_during_close = Arc::new(AtomicUsize::new(0));
            let mut sink = SlowClosingSink {
                polls: Arc::clone(&polls),
                polls_before_close: Arc::clone(&polls_before_close),
                polls_during_close: Arc::clone(&polls_during_close),
            };

            let result = stream_into(
                &mut sink,
                vec![Arc::new(SpinsOnSecondTargetProber {
                    polls: Arc::clone(&polls),
                })],
                &mut IngestFailsFuser,
                &NoopClassifier,
                None,
            )
            .await;

            assert!(refusal_detail(result).contains(INGEST_REFUSED));
            assert!(
                polls_before_close.load(Ordering::SeqCst) > 0,
                "the second target's probe must still be in flight when the fuser refused"
            );
            assert_eq!(
                polls_during_close.load(Ordering::SeqCst),
                0,
                "an abandoned scan must not keep probing while the sink closes"
            );
        }
    }
}
