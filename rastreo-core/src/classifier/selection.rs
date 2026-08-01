//! Classifier selection: name parsing and expansion into a `ClassifierConfig`.

use crate::classifier::{ClassifierConfig, MergeMode};
use crate::error::{ConfigError, RastreoError};

pub const CLASSIFIER_KIND_COUNT: usize = 2;

pub const DEFAULT_CLASSIFIER_KIND: ClassifierKind = ClassifierKind::Rules;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ClassifierKind {
    Noop,
    Rules,
}

impl ClassifierKind {
    pub const fn all() -> &'static [ClassifierKind; CLASSIFIER_KIND_COUNT] {
        &[ClassifierKind::Noop, ClassifierKind::Rules]
    }

    /// snake_case label, matching the `type:` discriminant of the matching [`ClassifierConfig`] variant.
    pub const fn label(self) -> &'static str {
        match self {
            ClassifierKind::Noop => "noop",
            ClassifierKind::Rules => "rules",
        }
    }

    /// Inverse of [`ClassifierKind::label`]; `None` for any string that is not a canonical label.
    pub fn from_label(label: &str) -> Option<ClassifierKind> {
        match label {
            "noop" => Some(ClassifierKind::Noop),
            "rules" => Some(ClassifierKind::Rules),
            _ => None,
        }
    }
}

pub fn parse_classifier_selection(value: &str) -> Result<ClassifierKind, RastreoError> {
    let name = value.trim();
    ClassifierKind::from_label(name).ok_or_else(|| unknown_classifier_kind(name))
}

pub fn expand_classifier_selection(
    kind: ClassifierKind,
    options: &ClassifierSelectionOptions,
) -> ClassifierConfig {
    match kind {
        ClassifierKind::Noop => ClassifierConfig::Noop,
        // Empty user lists under `Extend` resolve to the baked-in platform and role tables.
        ClassifierKind::Rules => ClassifierConfig::Rules {
            merge_mode: options.merge_mode.unwrap_or_default(),
            platform_rules: Vec::new(),
            role_rules: Vec::new(),
        },
    }
}

pub fn default_classifier_config() -> ClassifierConfig {
    expand_classifier_selection(
        DEFAULT_CLASSIFIER_KIND,
        &ClassifierSelectionOptions::default(),
    )
}

/// Knobs [`expand_classifier_selection`] applies; `None` leaves the classifier's own default.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ClassifierSelectionOptions {
    pub merge_mode: Option<MergeMode>,
}

fn unknown_classifier_kind(name: &str) -> RastreoError {
    let available: Vec<&'static str> = ClassifierKind::all()
        .iter()
        .map(|kind| kind.label())
        .collect();
    ConfigError::UnknownClassifierKind {
        name: name.to_string(),
        available: available.join(", "),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::classifier::create_classifier;

    fn config_error(err: RastreoError) -> ConfigError {
        match err {
            RastreoError::Config(err) => err,
            other => panic!("expected a config error, got {other:?}"),
        }
    }

    #[test]
    fn every_label_round_trips_through_from_label() {
        for kind in ClassifierKind::all().iter().copied() {
            assert_eq!(
                ClassifierKind::from_label(kind.label()),
                Some(kind),
                "{} did not round-trip",
                kind.label()
            );
        }
    }

    #[test]
    fn all_lists_every_kind_exactly_once() {
        let kinds = ClassifierKind::all();
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
    fn parse_accepts_every_canonical_label() {
        for kind in ClassifierKind::all().iter().copied() {
            assert_eq!(
                parse_classifier_selection(kind.label()).expect("labels always parse"),
                kind
            );
        }
    }

    #[test]
    fn parse_trims_whitespace_around_the_name() {
        assert_eq!(
            parse_classifier_selection("  noop\t").expect("parses"),
            ClassifierKind::Noop
        );
    }

    #[test]
    fn parse_rejects_an_unknown_name_and_lists_what_is_available() {
        let err = parse_classifier_selection("rule").expect_err("unknown name");
        match config_error(err) {
            ConfigError::UnknownClassifierKind { name, available } => {
                assert_eq!(name, "rule");
                for kind in ClassifierKind::all().iter().copied() {
                    assert!(
                        available.split(", ").any(|label| label == kind.label()),
                        "{} is missing from `{available}`",
                        kind.label()
                    );
                }
            }
            other => panic!("expected UnknownClassifierKind, got {other:?}"),
        }
    }

    #[test]
    fn the_unknown_classifier_error_names_no_cli_flag() {
        let message = parse_classifier_selection("rule")
            .expect_err("unknown name")
            .to_string();
        assert!(!message.contains("--"), "message: {message}");
    }

    #[test]
    fn every_kind_expands_into_a_config_whose_wire_tag_is_its_label() {
        for kind in ClassifierKind::all().iter().copied() {
            let config = expand_classifier_selection(kind, &ClassifierSelectionOptions::default());
            let json = serde_json::to_value(&config).expect("serializes");
            assert_eq!(json["type"], kind.label());
        }
    }

    #[test]
    fn every_kind_expands_into_a_classifier_the_factory_accepts() {
        for kind in ClassifierKind::all().iter().copied() {
            let config = expand_classifier_selection(kind, &ClassifierSelectionOptions::default());
            create_classifier(&config)
                .unwrap_or_else(|err| panic!("the factory rejected {}: {err}", kind.label()));
        }
    }

    #[test]
    fn the_merge_mode_knob_reaches_the_rules_config() {
        let options = ClassifierSelectionOptions {
            merge_mode: Some(MergeMode::Replace),
        };
        match expand_classifier_selection(ClassifierKind::Rules, &options) {
            ClassifierConfig::Rules { merge_mode, .. } => {
                assert_eq!(merge_mode, MergeMode::Replace);
            }
            other => panic!("expected Rules, got {other:?}"),
        }
    }

    #[test]
    fn an_unset_merge_mode_leaves_the_configs_own_default() {
        match expand_classifier_selection(
            ClassifierKind::Rules,
            &ClassifierSelectionOptions::default(),
        ) {
            ClassifierConfig::Rules { merge_mode, .. } => {
                assert_eq!(merge_mode, MergeMode::default());
            }
            other => panic!("expected Rules, got {other:?}"),
        }
    }

    #[test]
    fn expansion_supplies_no_user_rules_of_its_own() {
        match expand_classifier_selection(
            ClassifierKind::Rules,
            &ClassifierSelectionOptions::default(),
        ) {
            ClassifierConfig::Rules {
                platform_rules,
                role_rules,
                ..
            } => {
                assert!(platform_rules.is_empty());
                assert!(role_rules.is_empty());
            }
            other => panic!("expected Rules, got {other:?}"),
        }
    }

    #[test]
    fn the_default_config_is_the_default_kind_with_no_overrides() {
        assert_eq!(
            serde_json::to_value(default_classifier_config()).expect("serializes"),
            serde_json::to_value(expand_classifier_selection(
                DEFAULT_CLASSIFIER_KIND,
                &ClassifierSelectionOptions::default()
            ))
            .expect("serializes")
        );
    }

    #[test]
    fn the_default_classifier_applies_the_baked_rules() {
        assert_eq!(DEFAULT_CLASSIFIER_KIND, ClassifierKind::Rules);
        match default_classifier_config() {
            ClassifierConfig::Rules { merge_mode, .. } => {
                assert_eq!(
                    merge_mode,
                    MergeMode::Extend,
                    "the baked tables only run under Extend"
                );
            }
            other => panic!("expected Rules, got {other:?}"),
        }
    }

    #[test]
    fn selection_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ClassifierKind>();
        assert_send_sync::<ClassifierSelectionOptions>();
    }
}
