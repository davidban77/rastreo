use std::path::Path;

use schemars::JsonSchema;

use crate::atomic_file::write_atomically;
use crate::error::ReportError;
use crate::pipeline::DiscoverySummary;

/// Schema version of the run-report document.
pub const RUN_REPORT_VERSION: u32 = 1;

/// What one discovery run did: how every scenario it reached ended, and the run's totals.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, JsonSchema)]
#[non_exhaustive]
pub struct RunReport {
    /// Version of this document's shape. A consumer that does not recognise it cannot assume the field set.
    pub report_version: u32,
    /// One entry per scenario the run reached, in run order. Shorter than
    /// `aggregate.scenario_counts.total` when the run was cancelled before reaching the rest.
    pub scenarios: Vec<ScenarioReport>,
    pub aggregate: RunAggregate,
}

/// How one scenario the run reached ended; `skipped` is a scenario that declared no probers and never ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScenarioOutcome {
    Completed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, JsonSchema)]
#[non_exhaustive]
pub struct ScenarioReport {
    /// The scenario's own name, or `unnamed` when it declared none.
    pub scenario: String,
    pub outcome: ScenarioOutcome,
    /// Absent when the scenario produced none: it was skipped, or it failed before the scan returned one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<DiscoverySummary>,
}

impl ScenarioReport {
    pub fn new(
        scenario: String,
        outcome: ScenarioOutcome,
        summary: Option<DiscoverySummary>,
    ) -> Self {
        Self {
            scenario,
            outcome,
            summary,
        }
    }
}

/// The run's totals. `summary` folds every scenario's counters together, so its `elapsed_ms` is the
/// sum of the scenarios' durations rather than wall clock, and it attributes no `sink_type`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, JsonSchema)]
#[non_exhaustive]
pub struct RunAggregate {
    pub scenario_counts: ScenarioTally,
    pub summary: DiscoverySummary,
}

/// How many scenarios the run was asked for and how the ones it reached ended. `completed + failed +
/// skipped` is the fold over the report's entries, and falls short of `total` when the run was
/// cancelled before reaching the rest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, JsonSchema)]
pub struct ScenarioTally {
    pub total: usize,
    pub completed: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl ScenarioTally {
    fn over(scenarios: &[ScenarioReport], total: usize) -> Self {
        debug_assert!(
            total >= scenarios.len(),
            "more entries than scenarios asked for"
        );
        let mut tally = Self {
            total,
            ..Self::default()
        };
        for entry in scenarios {
            match entry.outcome {
                ScenarioOutcome::Completed => tally.completed += 1,
                ScenarioOutcome::Failed => tally.failed += 1,
                ScenarioOutcome::Skipped => tally.skipped += 1,
            }
        }
        tally
    }
}

impl RunReport {
    /// `total` is how many scenarios the run was asked for; `scenarios` are the ones it reached.
    pub fn new(scenarios: Vec<ScenarioReport>, total: usize, summary: DiscoverySummary) -> Self {
        Self {
            report_version: RUN_REPORT_VERSION,
            aggregate: RunAggregate {
                scenario_counts: ScenarioTally::over(&scenarios, total),
                summary,
            },
            scenarios,
        }
    }

    /// Persist atomically, so a reader never observes a partially written report.
    pub fn write(&self, path: impl AsRef<Path>) -> Result<(), ReportError> {
        let path = path.as_ref();
        // Infallible: no float, no non-string map key, and every duration renders as an integer.
        let bytes = serde_json::to_vec_pretty(self).expect("RunReport serialization is infallible");
        write_atomically(path, &bytes).map_err(|failure| ReportError::Persist {
            path: failure.path,
            source: failure.source,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::Duration;

    use serde_json::Value;

    use super::*;
    use crate::error::ProbeErrorKind;
    use crate::model::{ProbeFault, ProbeKind};
    use crate::pipeline::ProbeKindSummary;
    use crate::sink::{SinkErrorClass, SinkType};

    fn summary() -> DiscoverySummary {
        DiscoverySummary {
            targets_resolved: 2,
            probe_attempts: 4,
            records_emitted: 1,
            elapsed: Duration::from_millis(1200),
            sink_type: Some(SinkType::Stdout),
            ..DiscoverySummary::default()
        }
    }

    fn fully_populated() -> DiscoverySummary {
        let mut s = DiscoverySummary {
            links_emitted: 3,
            profiles_emitted: 1,
            dlq_records: 5,
            unresolvable_targets: vec!["stale.lab".to_string()],
            cancelled: true,
            probes_by_kind: vec![ProbeKindSummary {
                kind: ProbeKind::TcpConnect,
                attempted: 4,
                errored: 2,
                ..ProbeKindSummary::default()
            }],
            first_probe_error: Some(ProbeFault::new(
                ProbeErrorKind::PermissionDenied,
                "raw socket requires CAP_NET_RAW",
            )),
            dlq_records_by_type_and_class: vec![(SinkType::File, SinkErrorClass::WriteFailure, 5)],
            ..summary()
        };
        s.error_counts.insert(ProbeErrorKind::PermissionDenied, 2);
        s
    }

    fn entry(name: &str, outcome: ScenarioOutcome) -> ScenarioReport {
        let summary = match outcome {
            ScenarioOutcome::Completed => Some(fully_populated()),
            _ => None,
        };
        ScenarioReport::new(name.to_string(), outcome, summary)
    }

    fn report() -> RunReport {
        RunReport::new(
            vec![
                entry("office", ScenarioOutcome::Completed),
                entry("lab", ScenarioOutcome::Failed),
                entry("spare", ScenarioOutcome::Skipped),
            ],
            3,
            fully_populated(),
        )
    }

    fn keys(value: &Value) -> BTreeSet<String> {
        value
            .as_object()
            .expect("JSON object")
            .keys()
            .cloned()
            .collect()
    }

    fn keys_of(document: &Value, pointer: &str) -> BTreeSet<String> {
        keys(document.pointer(pointer).expect("pointer resolves"))
    }

    fn expected(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_string()).collect()
    }

    fn serialized() -> Value {
        serde_json::to_value(report()).expect("RunReport serializes")
    }

    #[test]
    fn the_document_key_set_is_the_one_consumers_were_promised() {
        assert_eq!(
            keys(&serialized()),
            expected(&["report_version", "scenarios", "aggregate"])
        );
    }

    #[test]
    fn the_aggregate_key_set_is_the_one_consumers_were_promised() {
        assert_eq!(
            keys_of(&serialized(), "/aggregate"),
            expected(&["scenario_counts", "summary"])
        );
    }

    #[test]
    fn the_scenario_entry_key_set_is_the_one_consumers_were_promised() {
        assert_eq!(
            keys_of(&serialized(), "/scenarios/0"),
            expected(&["scenario", "outcome", "summary"])
        );
    }

    #[test]
    fn an_entry_names_how_its_scenario_ended() {
        let document = serialized();
        assert_eq!(document["scenarios"][0]["outcome"], "completed");
        assert_eq!(document["scenarios"][1]["outcome"], "failed");
        assert_eq!(document["scenarios"][2]["outcome"], "skipped");
    }

    #[test]
    fn an_entry_whose_scenario_produced_no_summary_carries_none() {
        let document = serialized();
        assert!(document["scenarios"][0]["summary"].is_object());
        assert!(
            document["scenarios"][1].get("summary").is_none(),
            "a failed scenario's entry must not look like a successful one: {document}"
        );
        assert!(document["scenarios"][2].get("summary").is_none());
    }

    #[test]
    fn the_tally_is_the_fold_of_the_entries_by_outcome() {
        let counts = report().aggregate.scenario_counts;
        assert_eq!(
            (
                counts.total,
                counts.completed,
                counts.failed,
                counts.skipped
            ),
            (3, 1, 1, 1)
        );
    }

    #[test]
    fn a_run_cancelled_before_the_rest_tallies_fewer_scenarios_than_it_was_asked_for() {
        let report = RunReport::new(
            vec![entry("office", ScenarioOutcome::Completed)],
            4,
            fully_populated(),
        );
        let counts = report.aggregate.scenario_counts;
        assert_eq!(counts.total, 4);
        assert_eq!(counts.completed + counts.failed + counts.skipped, 1);
    }

    #[test]
    fn a_report_of_no_scenarios_tallies_none_of_them() {
        let counts = RunReport::new(Vec::new(), 2, DiscoverySummary::default())
            .aggregate
            .scenario_counts;
        assert_eq!((counts.completed, counts.failed, counts.skipped), (0, 0, 0));
    }

    #[test]
    fn the_scenario_count_key_set_is_the_one_consumers_were_promised() {
        assert_eq!(
            keys_of(&serialized(), "/aggregate/scenario_counts"),
            expected(&["total", "completed", "failed", "skipped"])
        );
    }

    #[test]
    fn a_new_report_carries_the_version_this_build_publishes() {
        assert_eq!(serialized()["report_version"], RUN_REPORT_VERSION);
    }

    #[test]
    fn a_scenario_entry_carries_the_summarys_own_sink_and_duration() {
        let document = serialized();
        assert_eq!(document["scenarios"][0]["summary"]["sink_type"], "stdout");
        assert_eq!(document["scenarios"][0]["summary"]["elapsed_ms"], 1200);
    }

    #[test]
    fn writing_a_report_leaves_a_readable_document_and_no_temporary_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("run.json");
        report().write(&path).expect("write");

        let raw = std::fs::read_to_string(&path).expect("read the report");
        let parsed: Value = serde_json::from_str(&raw).expect("the report is JSON");
        assert_eq!(parsed["aggregate"]["scenario_counts"]["skipped"], 1);
        assert!(!dir.path().join("run.json.tmp").exists());
    }

    #[test]
    fn a_second_run_replaces_the_report_of_the_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("run.json");
        report().write(&path).expect("write");
        RunReport::new(Vec::new(), 0, DiscoverySummary::default())
            .write(&path)
            .expect("rewrite");

        let raw = std::fs::read_to_string(&path).expect("read the report");
        let parsed: Value = serde_json::from_str(&raw).expect("the report is JSON");
        assert_eq!(parsed["scenarios"].as_array().expect("array").len(), 0);
    }

    #[test]
    fn an_unwritable_path_reports_the_path_it_failed_on() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing").join("run.json");
        let err = report().write(&path).expect_err("no such directory");
        assert!(
            err.to_string().contains("run.json"),
            "the failure names the path: {err}"
        );
    }

    #[test]
    fn the_schema_describes_the_document_a_consumer_reads() {
        let schema = schemars::schema_for!(RunReport);
        let value = serde_json::to_value(&schema).expect("schema serializes");
        assert_eq!(
            keys_of(&value, "/properties"),
            expected(&["report_version", "scenarios", "aggregate"])
        );
        assert!(
            value["$defs"]["DiscoverySummary"].is_object(),
            "the summary shape travels with the document: {value}"
        );
    }
}
