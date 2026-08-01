//! Fuser selection: name parsing and expansion into the one valid `FuserConfig` nesting.

use crate::error::{ConfigError, RastreoError};
use crate::fuser::{FuserConfig, IdentityHints};

pub const FUSER_KIND_COUNT: usize = 3;

// Higher ranks nest further out: the base innermost, enrichers over it, then the correlator
// `FuserConfig::validate` requires outermost.
const fn nesting_rank(kind: FuserKind) -> u8 {
    match kind {
        FuserKind::Direct => 0,
        FuserKind::MibEnrichment => 1,
        FuserKind::Identity => 2,
    }
}

/// Every fuser this crate knows by name, whether or not this build compiled it in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FuserKind {
    Direct,
    MibEnrichment,
    Identity,
}

impl FuserKind {
    pub const fn all() -> &'static [FuserKind; FUSER_KIND_COUNT] {
        &[
            FuserKind::Direct,
            FuserKind::MibEnrichment,
            FuserKind::Identity,
        ]
    }

    /// snake_case label, matching the `type:` discriminant of the matching [`FuserConfig`] variant.
    pub const fn label(self) -> &'static str {
        match self {
            FuserKind::Direct => "direct",
            FuserKind::MibEnrichment => "mib_enrichment",
            FuserKind::Identity => "identity",
        }
    }

    /// Inverse of [`FuserKind::label`]; `None` for any string that is not a canonical label.
    pub fn from_label(label: &str) -> Option<FuserKind> {
        match label {
            "direct" => Some(FuserKind::Direct),
            "mib_enrichment" => Some(FuserKind::MibEnrichment),
            "identity" => Some(FuserKind::Identity),
            _ => None,
        }
    }

    pub const fn is_compiled_in(self) -> bool {
        match self {
            FuserKind::Direct | FuserKind::Identity => true,
            FuserKind::MibEnrichment => cfg!(feature = "mib_enrichment"),
        }
    }

    pub const fn required_feature(self) -> Option<&'static str> {
        match self {
            FuserKind::Direct | FuserKind::Identity => None,
            FuserKind::MibEnrichment => Some("mib_enrichment"),
        }
    }
}

pub fn available_fuser_kinds() -> Vec<FuserKind> {
    FuserKind::all()
        .iter()
        .copied()
        .filter(|kind| kind.is_compiled_in())
        .collect()
}

pub fn default_fuser_config() -> FuserConfig {
    base_config(&FuserSelectionOptions::default())
}

/// Parses canonical [`FuserKind::label`] values, keeping the first occurrence of a repeated name.
pub fn parse_fuser_selection(values: &[String]) -> Result<Vec<FuserKind>, RastreoError> {
    let mut kinds: Vec<FuserKind> = Vec::new();
    for value in values {
        let name = value.trim();
        match FuserKind::from_label(name) {
            Some(kind) => {
                if !kinds.contains(&kind) {
                    kinds.push(kind);
                }
            }
            None => return Err(unknown_fuser_kind(name)),
        }
    }
    Ok(kinds)
}

/// Nests the named fusers the one way [`FuserConfig::validate`] accepts; a selection naming no base nests over [`default_fuser_config`].
pub fn expand_fuser_selection(
    kinds: &[FuserKind],
    options: &FuserSelectionOptions,
) -> Result<FuserConfig, RastreoError> {
    let mut ordered: Vec<FuserKind> = Vec::with_capacity(kinds.len());
    for kind in kinds.iter().copied() {
        if !ordered.contains(&kind) {
            ordered.push(kind);
        }
    }
    ordered.sort_unstable_by_key(|kind| nesting_rank(*kind));

    let mut config = base_config(options);
    for kind in ordered {
        config = compose(kind, config)?;
    }
    Ok(config)
}

/// Knobs [`expand_fuser_selection`] applies to the base fuser; `None` leaves the fuser's own default.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct FuserSelectionOptions {
    pub include_unreachable: Option<bool>,
    pub confidence_baseline: Option<f64>,
    pub confidence_per_signal: Option<f64>,
}

fn base_config(options: &FuserSelectionOptions) -> FuserConfig {
    FuserConfig::Direct {
        include_unreachable: options.include_unreachable,
        confidence_baseline: options.confidence_baseline,
        confidence_per_signal: options.confidence_per_signal,
    }
}

fn compose(kind: FuserKind, inner: FuserConfig) -> Result<FuserConfig, RastreoError> {
    match kind {
        // The base is already built, so naming it adds no layer.
        FuserKind::Direct => Ok(inner),
        FuserKind::MibEnrichment => {
            #[cfg(feature = "mib_enrichment")]
            {
                Ok(FuserConfig::MibEnrichment {
                    data_path: None,
                    inner: Box::new(inner),
                })
            }
            #[cfg(not(feature = "mib_enrichment"))]
            {
                Err(not_compiled(kind))
            }
        }
        FuserKind::Identity => Ok(FuserConfig::Identity {
            identity_hints: IdentityHints::default(),
            inner: Box::new(inner),
        }),
    }
}

fn unknown_fuser_kind(name: &str) -> RastreoError {
    let available: Vec<&'static str> = available_fuser_kinds()
        .iter()
        .map(|kind| kind.label())
        .collect();
    ConfigError::UnknownFuserKind {
        name: name.to_string(),
        available: available.join(", "),
    }
    .into()
}

#[allow(
    dead_code,
    reason = "every call site is a #[cfg(not(feature = ...))] composition arm"
)]
fn not_compiled(kind: FuserKind) -> RastreoError {
    let feature = match kind.required_feature() {
        Some(feature) => feature,
        None => kind.label(),
    };
    ConfigError::FuserKindNotCompiled {
        kind: kind.label(),
        feature,
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::checkpoint::fuser_supports_resume;

    fn tokens(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn config_error(err: RastreoError) -> ConfigError {
        match err {
            RastreoError::Config(err) => err,
            other => panic!("expected a config error, got {other:?}"),
        }
    }

    fn expand(kinds: &[FuserKind]) -> FuserConfig {
        expand_fuser_selection(kinds, &FuserSelectionOptions::default()).expect("expands")
    }

    fn layer_labels(config: &FuserConfig) -> Vec<&'static str> {
        let mut labels = Vec::new();
        let mut layer = config;
        loop {
            match layer {
                FuserConfig::Direct { .. } => {
                    labels.push(FuserKind::Direct.label());
                    return labels;
                }
                #[cfg(feature = "mib_enrichment")]
                FuserConfig::MibEnrichment { inner, .. } => {
                    labels.push(FuserKind::MibEnrichment.label());
                    layer = inner;
                }
                FuserConfig::Identity { inner, .. } => {
                    labels.push(FuserKind::Identity.label());
                    layer = inner;
                }
            }
        }
    }

    fn direct_knobs(config: &FuserConfig) -> (Option<bool>, Option<f64>, Option<f64>) {
        match config {
            FuserConfig::Direct {
                include_unreachable,
                confidence_baseline,
                confidence_per_signal,
            } => (
                *include_unreachable,
                *confidence_baseline,
                *confidence_per_signal,
            ),
            other => panic!("expected Direct, got {other:?}"),
        }
    }

    #[test]
    fn every_label_round_trips_through_from_label() {
        for kind in FuserKind::all().iter().copied() {
            assert_eq!(
                FuserKind::from_label(kind.label()),
                Some(kind),
                "{} did not round-trip",
                kind.label()
            );
        }
    }

    #[test]
    fn all_lists_every_kind_exactly_once() {
        let kinds = FuserKind::all();
        for kind in kinds.iter().copied() {
            assert_eq!(
                kinds.iter().filter(|other| **other == kind).count(),
                1,
                "{} appears more than once",
                kind.label()
            );
        }
    }

    #[test]
    fn every_kind_declares_a_nesting_rank_no_other_kind_shares() {
        for outer in FuserKind::all().iter().copied() {
            for inner in FuserKind::all().iter().copied() {
                if outer == inner {
                    continue;
                }
                assert_ne!(
                    nesting_rank(outer),
                    nesting_rank(inner),
                    "{} and {} share a nesting rank, so their stacking order is undefined",
                    outer.label(),
                    inner.label()
                );
            }
        }
    }

    #[test]
    fn the_correlator_ranks_outside_every_other_kind() {
        for kind in FuserKind::all().iter().copied() {
            if kind == FuserKind::Identity {
                continue;
            }
            assert!(
                nesting_rank(kind) < nesting_rank(FuserKind::Identity),
                "{} would nest outside identity, which validate() requires outermost",
                kind.label()
            );
        }
    }

    #[test]
    fn required_feature_is_none_only_for_kinds_present_in_every_build() {
        for kind in FuserKind::all().iter().copied() {
            if kind.required_feature().is_none() {
                assert!(
                    kind.is_compiled_in(),
                    "{} names no feature yet is absent from this build",
                    kind.label()
                );
            }
        }
    }

    #[test]
    fn available_fuser_kinds_lists_only_compiled_kinds() {
        for kind in available_fuser_kinds() {
            assert!(kind.is_compiled_in(), "{} is not compiled in", kind.label());
        }
        assert!(available_fuser_kinds().contains(&FuserKind::Direct));
        assert!(available_fuser_kinds().contains(&FuserKind::Identity));
    }

    #[test]
    fn parse_accepts_every_canonical_label_even_when_the_feature_is_absent() {
        for kind in FuserKind::all().iter().copied() {
            let selection =
                parse_fuser_selection(&tokens(&[kind.label()])).expect("labels always parse");
            assert_eq!(selection, vec![kind]);
        }
    }

    #[test]
    fn parse_trims_whitespace_around_each_token() {
        assert_eq!(
            parse_fuser_selection(&tokens(&[" identity ", "\tdirect"])).expect("parses"),
            vec![FuserKind::Identity, FuserKind::Direct]
        );
    }

    #[test]
    fn parse_dedups_keeping_first_occurrence() {
        assert_eq!(
            parse_fuser_selection(&tokens(&["identity", "direct", "identity"])).expect("parses"),
            vec![FuserKind::Identity, FuserKind::Direct]
        );
    }

    #[test]
    fn parse_of_no_values_yields_an_empty_selection() {
        assert!(parse_fuser_selection(&[]).expect("parses").is_empty());
    }

    #[test]
    fn parse_rejects_an_unknown_name_and_lists_what_this_build_offers() {
        let err = parse_fuser_selection(&tokens(&["identiy"])).expect_err("unknown name");
        match config_error(err) {
            ConfigError::UnknownFuserKind { name, available } => {
                assert_eq!(name, "identiy");
                for kind in FuserKind::all().iter().copied() {
                    assert_eq!(
                        available.split(", ").any(|label| label == kind.label()),
                        kind.is_compiled_in(),
                        "{} listed against its compilation state",
                        kind.label()
                    );
                }
            }
            other => panic!("expected UnknownFuserKind, got {other:?}"),
        }
    }

    #[test]
    fn the_unknown_fuser_error_names_no_cli_flag() {
        let err = parse_fuser_selection(&tokens(&["nope"])).expect_err("unknown name");
        let message = err.to_string();
        assert!(!message.contains("--"), "message: {message}");
    }

    #[test]
    fn naming_only_the_base_builds_no_wrapper() {
        assert_eq!(layer_labels(&expand(&[FuserKind::Direct])), vec!["direct"]);
    }

    #[test]
    fn naming_nothing_builds_the_default_base() {
        assert_eq!(layer_labels(&expand(&[])), vec!["direct"]);
        assert_eq!(
            layer_labels(&default_fuser_config()),
            layer_labels(&expand(&[]))
        );
    }

    #[test]
    fn identity_wraps_the_base_rather_than_replacing_it() {
        assert_eq!(
            layer_labels(&expand(&[FuserKind::Identity])),
            vec!["identity", "direct"]
        );
    }

    #[test]
    fn naming_the_base_and_the_correlator_puts_identity_outermost() {
        assert_eq!(
            layer_labels(&expand(&[FuserKind::Identity, FuserKind::Direct])),
            vec!["identity", "direct"]
        );
    }

    #[test]
    fn the_order_the_names_arrive_in_does_not_change_the_tree() {
        assert_eq!(
            layer_labels(&expand(&[FuserKind::Direct, FuserKind::Identity])),
            layer_labels(&expand(&[FuserKind::Identity, FuserKind::Direct]))
        );
    }

    #[cfg(feature = "mib_enrichment")]
    #[test]
    fn an_enricher_sits_between_the_correlator_and_the_base() {
        assert_eq!(
            layer_labels(&expand(&[
                FuserKind::MibEnrichment,
                FuserKind::Identity,
                FuserKind::Direct,
            ])),
            vec!["identity", "mib_enrichment", "direct"]
        );
    }

    #[test]
    fn every_expanded_selection_passes_the_validation_it_will_face_at_construction() {
        for kinds in every_compiled_subset() {
            let config = expand_fuser_selection(&kinds, &FuserSelectionOptions::default())
                .expect("compiled kinds expand");
            config.validate().unwrap_or_else(|err| {
                panic!(
                    "expansion of {:?} built a tree validate() rejects: {err}",
                    labels_of(&kinds)
                )
            });
            crate::fuser::create_fuser(&config).unwrap_or_else(|err| {
                panic!("the factory rejected {:?}: {err}", labels_of(&kinds))
            });
        }
    }

    fn labels_of(kinds: &[FuserKind]) -> Vec<&'static str> {
        kinds.iter().map(|kind| kind.label()).collect()
    }

    fn every_compiled_subset() -> Vec<Vec<FuserKind>> {
        every_subset(&available_fuser_kinds())
    }

    fn every_subset(kinds: &[FuserKind]) -> Vec<Vec<FuserKind>> {
        (0..(1u32 << kinds.len()))
            .map(|mask| {
                kinds
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << i) != 0)
                    .map(|(_, kind)| *kind)
                    .collect()
            })
            .collect()
    }

    #[test]
    fn expansion_accounts_for_every_named_kind_as_a_layer_or_as_an_error() {
        for kinds in every_subset(FuserKind::all()) {
            match expand_fuser_selection(&kinds, &FuserSelectionOptions::default()) {
                Ok(config) => {
                    let layers = layer_labels(&config);
                    for kind in &kinds {
                        assert!(
                            layers.contains(&kind.label()),
                            "{} was named yet the tree {layers:?} carries no such layer",
                            kind.label()
                        );
                    }
                }
                Err(err) => match config_error(err) {
                    ConfigError::FuserKindNotCompiled { kind: named, .. } => {
                        let refused = FuserKind::from_label(named).expect("a canonical label");
                        assert!(
                            kinds.contains(&refused) && !refused.is_compiled_in(),
                            "expansion of {:?} refused {named}, which it was not asked for",
                            labels_of(&kinds)
                        );
                    }
                    other => panic!("expected FuserKindNotCompiled, got {other:?}"),
                },
            }
        }
    }

    #[test]
    fn a_repeated_kind_still_builds_one_layer_of_it() {
        assert_eq!(
            layer_labels(&expand(&[
                FuserKind::Identity,
                FuserKind::Identity,
                FuserKind::Direct,
            ])),
            vec!["identity", "direct"]
        );
    }

    #[test]
    fn every_compiled_kind_expands_into_a_layer_whose_wire_tag_is_its_label() {
        for kind in available_fuser_kinds() {
            let json = serde_json::to_value(expand(&[kind])).expect("serializes");
            assert_eq!(
                json["type"],
                kind.label(),
                "{} expands into a layer tagged otherwise",
                kind.label()
            );
        }
    }

    #[test]
    fn the_knobs_reach_the_base_of_a_wrapped_tree() {
        let options = FuserSelectionOptions {
            include_unreachable: Some(true),
            confidence_baseline: Some(0.42),
            confidence_per_signal: Some(0.07),
        };
        let config =
            expand_fuser_selection(&[FuserKind::Identity], &options).expect("identity expands");
        let FuserConfig::Identity { inner, .. } = &config else {
            panic!("expected Identity, got {config:?}");
        };
        assert_eq!(
            direct_knobs(inner),
            (Some(true), Some(0.42), Some(0.07)),
            "the knobs must reach the base under the correlator"
        );
    }

    #[test]
    fn unset_knobs_stay_absent_so_the_fuser_keeps_its_own_defaults() {
        assert_eq!(
            direct_knobs(&expand(&[FuserKind::Direct])),
            (None, None, None)
        );
    }

    #[test]
    fn include_unreachable_reaches_the_built_fuser() {
        use crate::fuser::{create_fuser, drive_fuser};
        use crate::model::outcome::{ProbeKind, ProbeOutcome};
        use std::net::{IpAddr, Ipv4Addr};
        use std::time::SystemTime;

        let options = FuserSelectionOptions {
            include_unreachable: Some(true),
            ..Default::default()
        };
        let config = expand_fuser_selection(&[FuserKind::Direct], &options).expect("expands");
        let mut fuser = create_fuser(&config).expect("factory accepts the config");
        let outcome = ProbeOutcome {
            lldp: None,
            gnmi_endpoint: None,
            kind: ProbeKind::TcpConnect,
            target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            timestamp: SystemTime::UNIX_EPOCH,
            reachable: false,
            signals: Vec::new(),
            fault: None,
        };
        let records = drive_fuser(fuser.as_mut(), vec![outcome]).expect("fuses");
        assert_eq!(
            records.len(),
            1,
            "a selection asking for unreachable targets must emit the silent one"
        );
    }

    #[test]
    fn the_confidence_knobs_reach_the_built_fuser() {
        use crate::fuser::{create_fuser, drive_fuser};
        use crate::model::outcome::{ProbeKind, ProbeOutcome, Signal};
        use std::net::{IpAddr, Ipv4Addr};
        use std::time::SystemTime;

        let options = FuserSelectionOptions {
            confidence_baseline: Some(0.5),
            confidence_per_signal: Some(0.05),
            ..Default::default()
        };
        let config = expand_fuser_selection(&[FuserKind::Direct], &options).expect("expands");
        let mut fuser = create_fuser(&config).expect("factory accepts the config");
        let outcome = ProbeOutcome {
            lldp: None,
            gnmi_endpoint: None,
            kind: ProbeKind::TcpConnect,
            target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            timestamp: SystemTime::UNIX_EPOCH,
            reachable: true,
            signals: vec![Signal::OpenPort(22), Signal::OpenPort(80)],
            fault: None,
        };
        let records = drive_fuser(fuser.as_mut(), vec![outcome]).expect("fuses");
        assert!((records[0].confidence.value() - 0.6).abs() < 1e-9);
    }

    #[test]
    fn a_selection_naming_identity_is_refused_by_the_resume_check() {
        for kind in available_fuser_kinds() {
            assert_eq!(
                fuser_supports_resume(&expand(&[kind])),
                kind != FuserKind::Identity,
                "{} disagrees with the checkpoint's resume verdict",
                kind.label()
            );
        }
    }

    #[test]
    fn a_selection_carrying_identity_under_a_wrapper_is_still_refused() {
        let kinds = available_fuser_kinds();
        assert!(
            !fuser_supports_resume(&expand(&kinds)),
            "a selection naming every kind carries identity and cannot resume"
        );
    }

    #[cfg(not(feature = "mib_enrichment"))]
    #[test]
    fn a_fuser_left_out_of_the_build_fails_at_expansion_not_at_parse() {
        let selection =
            parse_fuser_selection(&tokens(&["mib_enrichment"])).expect("the name still parses");
        let err = expand_fuser_selection(&selection, &FuserSelectionOptions::default())
            .expect_err("mib_enrichment is not compiled in");
        match config_error(err) {
            ConfigError::FuserKindNotCompiled { kind, feature } => {
                assert_eq!(kind, "mib_enrichment");
                assert_eq!(feature, "mib_enrichment");
            }
            other => panic!("expected FuserKindNotCompiled, got {other:?}"),
        }
    }

    #[test]
    fn every_uncompiled_kind_reports_its_missing_feature_rather_than_a_bad_name() {
        for kind in FuserKind::all().iter().copied() {
            if kind.is_compiled_in() {
                continue;
            }
            let err = expand_fuser_selection(&[kind], &FuserSelectionOptions::default())
                .expect_err("uncompiled kinds cannot expand");
            match config_error(err) {
                ConfigError::FuserKindNotCompiled {
                    kind: named,
                    feature,
                } => {
                    assert_eq!(named, kind.label());
                    assert_eq!(Some(feature), kind.required_feature());
                }
                other => panic!(
                    "expected FuserKindNotCompiled for {}, got {other:?}",
                    kind.label()
                ),
            }
        }
    }

    #[test]
    fn selection_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FuserKind>();
        assert_send_sync::<FuserSelectionOptions>();
    }
}
