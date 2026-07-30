use serde_yaml_ng::Value;

use crate::error::ConfigError;

/// The config file being expanded, named in the error when a referenced variable is unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretSource {
    Scenario,
    SinkConfig,
}

impl SecretSource {
    fn reference_label(self) -> &'static str {
        match self {
            SecretSource::Scenario => "scenario",
            SecretSource::SinkConfig => "sink config",
        }
    }

    pub(crate) fn shape_label(self) -> &'static str {
        match self {
            SecretSource::Scenario => "scenario",
            SecretSource::SinkConfig => "sink",
        }
    }
}

/// Recursively expand `${VAR}` env-var references in string scalars and read `!file <path>` tagged scalars into their file contents. YAML mapping keys are left unmodified.
pub(crate) fn expand(value: Value, source: SecretSource) -> Result<Value, ConfigError> {
    match value {
        Value::String(s) => Ok(Value::String(interpolate_env(&s, source)?)),
        Value::Tagged(tagged) => {
            if tagged.tag == "file" {
                let path = match tagged.value {
                    Value::String(p) => p,
                    other => {
                        return Err(ConfigError::invalid(format!(
                            "!file tag expects a string scalar path, got {}",
                            yaml_type_name(&other)
                        )));
                    }
                };
                Ok(Value::String(read_file_secret(&path)?))
            } else {
                let inner = expand(tagged.value, source)?;
                Ok(Value::Tagged(Box::new(serde_yaml_ng::value::TaggedValue {
                    tag: tagged.tag,
                    value: inner,
                })))
            }
        }
        Value::Sequence(seq) => {
            let mut out = Vec::with_capacity(seq.len());
            for item in seq {
                out.push(expand(item, source)?);
            }
            Ok(Value::Sequence(out))
        }
        Value::Mapping(mut map) => {
            for (_key, v) in map.iter_mut() {
                // On error, this leaves `Null` in place of one value; caller must drop the
                // partially-transformed tree.
                let taken = std::mem::replace(v, Value::Null);
                *v = expand(taken, source)?;
            }
            Ok(Value::Mapping(map))
        }
        other => Ok(other),
    }
}

/// Detail for a shape error raised over the *expanded* tree, derived by re-deserializing the tree
/// **as written**: the text can then only quote a `${VAR}` reference or an `!file` path, never the
/// value one expanded to.
///
/// Both transforms preserve shape and rewrite only string contents, so reference-form and expanded
/// fail at the same position — every field type either accepts both a reference and a value, or
/// rejects both. That is what makes the reported position faithful and the `Ok` arm unreachable.
pub(crate) fn shape_failure_detail<T: serde::de::DeserializeOwned>(raw: &Value) -> String {
    match serde_yaml_ng::from_value::<T>(reference_form(raw)) {
        Err(err) if contains_secret_reference(raw) => format!("{err} {REFERENCE_FORM_NOTE}"),
        Err(err) => err.to_string(),
        Ok(_) => "a value substituted from a `${VAR}` reference or an `!file` tag does not fit its field (the substituted value is not shown)".to_string(),
    }
}

const REFERENCE_FORM_NOTE: &str = "(references resolved; quoted as written, never as the value produced; expansion substitutes a string, so a reference can only fill a field that accepts one)";

/// The tree as written, with `!file` tags flattened to their literal reference text so that a shape
/// error over an `!file` position names the path instead of failing on the YAML tag itself.
fn reference_form(value: &Value) -> Value {
    match value {
        Value::Tagged(tagged) => match &tagged.value {
            Value::String(path) if tagged.tag == "file" => Value::String(format!("!file {path}")),
            inner => Value::Tagged(Box::new(serde_yaml_ng::value::TaggedValue {
                tag: tagged.tag.clone(),
                value: reference_form(inner),
            })),
        },
        Value::Sequence(seq) => Value::Sequence(seq.iter().map(reference_form).collect()),
        Value::Mapping(map) => Value::Mapping(
            map.iter()
                .map(|(key, v)| (key.clone(), reference_form(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn contains_secret_reference(value: &Value) -> bool {
    match value {
        Value::String(s) => s.contains("${"),
        Value::Tagged(tagged) => tagged.tag == "file" || contains_secret_reference(&tagged.value),
        Value::Sequence(seq) => seq.iter().any(contains_secret_reference),
        Value::Mapping(map) => map.values().any(contains_secret_reference),
        _ => false,
    }
}

fn interpolate_env(input: &str, source: SecretSource) -> Result<String, ConfigError> {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut copy_start = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }
        if i + 2 < bytes.len() && bytes[i + 1] == b'$' && bytes[i + 2] == b'{' {
            if let Some(end) = find_ref_end(bytes, i + 1) {
                out.push_str(&input[copy_start..i]);
                out.push_str(&input[i + 1..=end]);
                i = end + 1;
                copy_start = i;
                continue;
            }
        }
        if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            if let Some(end) = find_ref_end(bytes, i) {
                let name = &input[i + 2..end];
                if is_valid_identifier(name) {
                    let value = std::env::var(name).map_err(|_| {
                        ConfigError::invalid(format!(
                            "environment variable {name} referenced in {} is not set",
                            source.reference_label()
                        ))
                    })?;
                    out.push_str(&input[copy_start..i]);
                    out.push_str(&value);
                    i = end + 1;
                    copy_start = i;
                    continue;
                }
            }
        }
        i += 1;
    }
    out.push_str(&input[copy_start..]);
    Ok(out)
}

fn find_ref_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start).copied() != Some(b'$') || bytes.get(start + 1).copied() != Some(b'{') {
        return None;
    }
    let mut j = start + 2;
    while j < bytes.len() {
        if bytes[j] == b'}' {
            return Some(j);
        }
        j += 1;
    }
    None
}

fn is_valid_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn read_file_secret(path: &str) -> Result<String, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(contents.trim_end().to_string()),
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => Err(ConfigError::invalid(format!(
                "file secret {path} not found"
            ))),
            std::io::ErrorKind::PermissionDenied => Err(ConfigError::invalid(format!(
                "file secret {path} not readable: permission denied"
            ))),
            _ => Err(ConfigError::invalid(format!(
                "file secret {path} could not be read: {err}"
            ))),
        },
    }
}

fn yaml_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Sequence(_) => "sequence",
        Value::Mapping(_) => "mapping",
        Value::Tagged(_) => "tagged",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml_ng::value::{Tag, TaggedValue};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn set_var(name: &str, value: &str) {
        // SAFETY: env var mutation is process-global. Tests use unique per-test names to avoid interaction.
        unsafe { std::env::set_var(name, value) };
    }

    fn remove_var(name: &str) {
        // SAFETY: env var mutation is process-global. Tests use unique per-test names to avoid interaction.
        unsafe { std::env::remove_var(name) };
    }

    fn expand_scenario(value: Value) -> Result<Value, ConfigError> {
        expand(value, SecretSource::Scenario)
    }

    #[test]
    fn expand_replaces_single_env_var() {
        set_var("RASTREO_TEST_SECRETS_SINGLE", "bar");
        let out = expand_scenario(Value::String("${RASTREO_TEST_SECRETS_SINGLE}".into()))
            .expect("expand");
        assert_eq!(out, Value::String("bar".into()));
        remove_var("RASTREO_TEST_SECRETS_SINGLE");
    }

    #[test]
    fn expand_replaces_multiple_env_vars_in_one_string() {
        set_var("RASTREO_TEST_SECRETS_MULTI_A", "foo");
        set_var("RASTREO_TEST_SECRETS_MULTI_B", "bar");
        let out = expand_scenario(Value::String(
            "${RASTREO_TEST_SECRETS_MULTI_A}-${RASTREO_TEST_SECRETS_MULTI_B}".into(),
        ))
        .expect("expand");
        assert_eq!(out, Value::String("foo-bar".into()));
        remove_var("RASTREO_TEST_SECRETS_MULTI_A");
        remove_var("RASTREO_TEST_SECRETS_MULTI_B");
    }

    #[test]
    fn expand_preserves_surrounding_text() {
        set_var("RASTREO_TEST_SECRETS_SURROUND", "middle");
        let out = expand_scenario(Value::String(
            "prefix-${RASTREO_TEST_SECRETS_SURROUND}-suffix".into(),
        ))
        .expect("expand");
        assert_eq!(out, Value::String("prefix-middle-suffix".into()));
        remove_var("RASTREO_TEST_SECRETS_SURROUND");
    }

    #[test]
    fn expand_missing_env_var_returns_actionable_error() {
        remove_var("RASTREO_TEST_SECRETS_MISSING_XYZ");
        let err = expand_scenario(Value::String("${RASTREO_TEST_SECRETS_MISSING_XYZ}".into()))
            .expect_err("must error");
        let msg = format!("{err}");
        assert!(
            msg.contains("RASTREO_TEST_SECRETS_MISSING_XYZ"),
            "msg: {msg}"
        );
        assert!(msg.contains("not set"), "msg: {msg}");
    }

    #[test]
    fn expand_missing_env_var_names_the_config_it_was_referenced_from() {
        remove_var("RASTREO_TEST_SECRETS_SOURCE_LABEL");
        for (source, expected, other) in [
            (SecretSource::Scenario, "scenario", "sink config"),
            (SecretSource::SinkConfig, "sink config", "scenario"),
        ] {
            let err = expand(
                Value::String("${RASTREO_TEST_SECRETS_SOURCE_LABEL}".into()),
                source,
            )
            .expect_err("must error");
            let msg = format!("{err}");
            assert!(msg.contains(expected), "{source:?} msg: {msg}");
            assert!(!msg.contains(other), "{source:?} msg: {msg}");
        }
    }

    #[test]
    fn expand_empty_env_var_substitutes_as_empty_string() {
        set_var("RASTREO_TEST_SECRETS_EMPTY", "");
        let out = expand_scenario(Value::String(
            "prefix-${RASTREO_TEST_SECRETS_EMPTY}-suffix".into(),
        ))
        .expect("expand");
        assert_eq!(out, Value::String("prefix--suffix".into()));
        remove_var("RASTREO_TEST_SECRETS_EMPTY");
    }

    #[test]
    fn expand_escape_sequence_preserves_literal() {
        set_var("RASTREO_TEST_SECRETS_ESCAPE", "should-not-be-used");
        let out = expand_scenario(Value::String("$${RASTREO_TEST_SECRETS_ESCAPE}".into()))
            .expect("expand");
        assert_eq!(out, Value::String("${RASTREO_TEST_SECRETS_ESCAPE}".into()));
        remove_var("RASTREO_TEST_SECRETS_ESCAPE");
    }

    #[test]
    fn expand_recurses_into_sequences_and_mappings() {
        set_var("RASTREO_TEST_SECRETS_NESTED", "value");
        let yaml = "\
outer:
  inner:
    - plain
    - \"prefix-${RASTREO_TEST_SECRETS_NESTED}\"
";
        let raw: Value = serde_yaml_ng::from_str(yaml).expect("parse");
        let out = expand_scenario(raw).expect("expand");
        let outer = out.get("outer").expect("outer");
        let inner = outer.get("inner").expect("inner");
        let seq = inner.as_sequence().expect("sequence");
        assert_eq!(seq[0], Value::String("plain".into()));
        assert_eq!(seq[1], Value::String("prefix-value".into()));
        remove_var("RASTREO_TEST_SECRETS_NESTED");
    }

    #[test]
    fn expand_does_not_expand_map_keys() {
        set_var("RASTREO_TEST_SECRETS_KEY", "would-be-key");
        let mut map = serde_yaml_ng::Mapping::new();
        map.insert(
            Value::String("${RASTREO_TEST_SECRETS_KEY}".into()),
            Value::String("v".into()),
        );
        let out = expand_scenario(Value::Mapping(map)).expect("expand");
        let mapping = out.as_mapping().expect("mapping");
        let keys: Vec<_> = mapping.keys().collect();
        assert_eq!(
            keys[0],
            &Value::String("${RASTREO_TEST_SECRETS_KEY}".into())
        );
        remove_var("RASTREO_TEST_SECRETS_KEY");
    }

    #[test]
    fn expand_does_not_affect_non_string_scalars() {
        assert_eq!(
            expand_scenario(Value::Bool(true)).expect("bool"),
            Value::Bool(true)
        );
        assert_eq!(expand_scenario(Value::Null).expect("null"), Value::Null);
        let n = Value::Number(serde_yaml_ng::Number::from(42u64));
        assert_eq!(expand_scenario(n.clone()).expect("num"), n);
    }

    #[test]
    fn expand_identifier_pattern_rejects_bare_dollar_brace() {
        let out = expand_scenario(Value::String("${".into())).expect("expand");
        assert_eq!(out, Value::String("${".into()));
        let out = expand_scenario(Value::String("${1foo}".into())).expect("expand");
        assert_eq!(out, Value::String("${1foo}".into()));
        let out = expand_scenario(Value::String("${a-b}".into())).expect("expand");
        assert_eq!(out, Value::String("${a-b}".into()));
    }

    #[test]
    fn expand_file_tag_reads_file_contents() {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(b"the-secret").expect("write");
        let path = f.path().to_str().expect("utf-8 path").to_string();
        let tagged = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("file"),
            value: Value::String(path),
        }));
        let out = expand_scenario(tagged).expect("expand");
        assert_eq!(out, Value::String("the-secret".into()));
    }

    #[test]
    fn expand_file_tag_trims_trailing_newline() {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(b"secret\n").expect("write");
        let path = f.path().to_str().expect("utf-8 path").to_string();
        let tagged = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("file"),
            value: Value::String(path),
        }));
        let out = expand_scenario(tagged).expect("expand");
        assert_eq!(out, Value::String("secret".into()));
    }

    #[test]
    fn expand_file_tag_preserves_leading_whitespace() {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(b"  secret\n").expect("write");
        let path = f.path().to_str().expect("utf-8 path").to_string();
        let tagged = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("file"),
            value: Value::String(path),
        }));
        let out = expand_scenario(tagged).expect("expand");
        assert_eq!(out, Value::String("  secret".into()));
    }

    #[test]
    fn expand_file_tag_missing_file_returns_actionable_error() {
        let tagged = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("file"),
            value: Value::String("/nonexistent/rastreo/test/path/xyzzy".into()),
        }));
        let err = expand_scenario(tagged).expect_err("must error");
        let msg = format!("{err}");
        assert!(
            msg.contains("/nonexistent/rastreo/test/path/xyzzy"),
            "msg: {msg}"
        );
        assert!(msg.contains("not found"), "msg: {msg}");
    }

    #[test]
    fn expand_file_tag_recurses_into_nested_structures() {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(b"deep-secret").expect("write");
        let path = f.path().to_str().expect("utf-8 path").to_string();
        let yaml = format!(
            "\
credentials:
  auth:
    password: !file {path}
"
        );
        let raw: Value = serde_yaml_ng::from_str(&yaml).expect("parse");
        let out = expand_scenario(raw).expect("expand");
        let creds = out.get("credentials").expect("credentials");
        let auth = creds.get("auth").expect("auth");
        let pw = auth.get("password").expect("password");
        assert_eq!(pw, &Value::String("deep-secret".into()));
    }

    #[test]
    fn expand_file_tag_non_string_scalar_returns_error() {
        let tagged = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("file"),
            value: Value::Number(serde_yaml_ng::Number::from(42u64)),
        }));
        let err = expand_scenario(tagged).expect_err("must error");
        let msg = format!("{err}");
        assert!(msg.contains("!file"), "msg: {msg}");
        assert!(msg.contains("string"), "msg: {msg}");
    }

    #[test]
    fn expand_leaves_unknown_tags_unchanged() {
        let tagged = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("Custom"),
            value: Value::String("value".into()),
        }));
        let out = expand_scenario(tagged).expect("expand");
        match out {
            Value::Tagged(t) => {
                assert!(t.tag == "Custom");
                assert_eq!(t.value, Value::String("value".into()));
            }
            other => panic!("expected Tagged, got {other:?}"),
        }
    }

    #[test]
    fn expand_preserves_non_ascii_string_content() {
        set_var("RASTREO_TEST_SECRETS_UTF8", "x");
        let out = expand_scenario(Value::String("café-${RASTREO_TEST_SECRETS_UTF8}".into()))
            .expect("expand");
        assert_eq!(out, Value::String("café-x".into()));
        remove_var("RASTREO_TEST_SECRETS_UTF8");
    }

    #[test]
    fn expand_preserves_unicode_string_with_no_interpolation() {
        let out = expand_scenario(Value::String("naïve".into())).expect("expand");
        assert_eq!(out, Value::String("naïve".into()));
    }

    #[test]
    fn expand_recurses_into_unknown_tag_body() {
        set_var("RASTREO_TEST_SECRETS_TAGGED", "value");
        let tagged = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("Custom"),
            value: Value::String("prefix-${RASTREO_TEST_SECRETS_TAGGED}-suffix".into()),
        }));
        let out = expand_scenario(tagged).expect("expand");
        match out {
            Value::Tagged(t) => {
                assert!(t.tag == "Custom");
                assert_eq!(t.value, Value::String("prefix-value-suffix".into()));
            }
            other => panic!("expected Tagged, got {other:?}"),
        }
        remove_var("RASTREO_TEST_SECRETS_TAGGED");
    }

    #[test]
    fn shape_failure_detail_quotes_an_env_reference_as_written() {
        set_var("RASTREO_TEST_SECRETS_SHAPE_ENV", "the-secret");
        let raw: Value = serde_yaml_ng::from_str("value: \"${RASTREO_TEST_SECRETS_SHAPE_ENV}\"\n")
            .expect("yaml");
        let detail = shape_failure_detail::<std::collections::HashMap<String, u8>>(&raw);
        assert!(
            detail.contains("${RASTREO_TEST_SECRETS_SHAPE_ENV}"),
            "detail: {detail}"
        );
        assert!(!detail.contains("the-secret"), "detail: {detail}");
        assert!(detail.contains("quoted as written"), "detail: {detail}");
        remove_var("RASTREO_TEST_SECRETS_SHAPE_ENV");
    }

    #[test]
    fn shape_failure_detail_quotes_a_file_reference_as_its_path_without_reading_it() {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(b"the-secret").expect("write");
        let path = f.path().to_str().expect("utf-8 path").to_string();
        let raw: Value = serde_yaml_ng::from_str(&format!("value: !file {path}\n")).expect("yaml");
        let detail = shape_failure_detail::<std::collections::HashMap<String, u8>>(&raw);
        assert!(
            detail.contains(&format!("!file {path}")),
            "detail: {detail}"
        );
        assert!(!detail.contains("the-secret"), "detail: {detail}");
    }

    #[test]
    fn shape_failure_detail_omits_the_note_when_the_tree_has_no_reference() {
        let raw: Value = serde_yaml_ng::from_str("value: plain\n").expect("yaml");
        let detail = shape_failure_detail::<std::collections::HashMap<String, u8>>(&raw);
        assert!(detail.contains("invalid type"), "detail: {detail}");
        assert!(!detail.contains("reference"), "detail: {detail}");
    }

    // A type that accepts the tree as written leaves only the substituted value to blame.
    #[test]
    fn shape_failure_detail_names_the_substitution_when_the_tree_as_written_is_valid() {
        set_var("RASTREO_TEST_SECRETS_SHAPE_VALID", "the-secret");
        let raw: Value =
            serde_yaml_ng::from_str("value: \"${RASTREO_TEST_SECRETS_SHAPE_VALID}\"\n")
                .expect("yaml");
        let detail = shape_failure_detail::<std::collections::HashMap<String, String>>(&raw);
        assert!(!detail.contains("the-secret"), "detail: {detail}");
        assert!(
            detail.contains("does not fit its field"),
            "detail: {detail}"
        );
        assert!(detail.contains("is not shown"), "detail: {detail}");
        remove_var("RASTREO_TEST_SECRETS_SHAPE_VALID");
    }

    type StringlyTypedField = crate::config::ScenarioKind;

    fn reference_at_one_position() -> Value {
        serde_yaml_ng::from_str("value: \"${RASTREO_TEST_NOTE_REFERENCE}\"\n").expect("yaml")
    }

    #[test]
    fn the_note_claims_no_secrecy_for_a_reference_in_a_field_that_holds_none() {
        let raw = reference_at_one_position();
        for detail in [
            shape_failure_detail::<std::collections::HashMap<String, u32>>(&raw),
            shape_failure_detail::<std::collections::HashMap<String, bool>>(&raw),
            shape_failure_detail::<std::collections::HashMap<String, Vec<String>>>(&raw),
            shape_failure_detail::<std::collections::HashMap<String, StringlyTypedField>>(&raw),
        ] {
            let lowered = detail.to_lowercase();
            assert!(!lowered.contains("secret"), "detail: {detail}");
            assert!(!lowered.contains("withheld"), "detail: {detail}");
            assert!(!lowered.contains("hidden"), "detail: {detail}");
        }
    }

    #[test]
    fn the_note_states_that_the_references_resolved() {
        let raw = reference_at_one_position();
        let detail = shape_failure_detail::<std::collections::HashMap<String, u32>>(&raw);
        assert!(detail.contains("references resolved"), "detail: {detail}");
    }

    #[test]
    fn the_note_is_the_same_for_a_reference_in_a_numeric_field_and_in_a_stringly_typed_one() {
        const NOTE: &str = "(references resolved; quoted as written, never as the value produced; expansion substitutes a string, so a reference can only fill a field that accepts one)";
        let raw = reference_at_one_position();
        let numeric = shape_failure_detail::<std::collections::HashMap<String, u32>>(&raw);
        let stringly =
            shape_failure_detail::<std::collections::HashMap<String, StringlyTypedField>>(&raw);
        assert!(numeric.ends_with(NOTE), "detail: {numeric}");
        assert!(stringly.ends_with(NOTE), "detail: {stringly}");
    }

    #[test]
    fn reference_form_leaves_env_references_and_plain_scalars_untouched() {
        let yaml = "outer:\n  inner:\n    - plain\n    - \"prefix-${SOME_VAR}\"\n  count: 3\n";
        let raw: Value = serde_yaml_ng::from_str(yaml).expect("parse");
        assert_eq!(reference_form(&raw), raw);
    }

    #[test]
    fn reference_form_renders_a_nested_file_tag_as_its_reference_text() {
        let yaml = "credentials:\n  auth:\n    password: !file /run/secrets/pw\n";
        let raw: Value = serde_yaml_ng::from_str(yaml).expect("parse");
        let rendered = reference_form(&raw);
        let pw = rendered
            .get("credentials")
            .and_then(|c| c.get("auth"))
            .and_then(|a| a.get("password"))
            .expect("password");
        assert_eq!(pw, &Value::String("!file /run/secrets/pw".into()));
    }

    #[test]
    fn reference_form_keeps_unknown_tags_and_recurses_into_them() {
        let tagged = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("Custom"),
            value: Value::Sequence(vec![Value::Tagged(Box::new(TaggedValue {
                tag: Tag::new("file"),
                value: Value::String("/run/secrets/pw".into()),
            }))]),
        }));
        match reference_form(&tagged) {
            Value::Tagged(t) => {
                assert!(t.tag == "Custom");
                assert_eq!(
                    t.value,
                    Value::Sequence(vec![Value::String("!file /run/secrets/pw".into())])
                );
            }
            other => panic!("expected Tagged, got {other:?}"),
        }
    }

    #[test]
    fn expand_file_tag_non_utf8_contents_returns_error_naming_path() {
        let f = NamedTempFile::new().expect("tempfile");
        let path = f.path().to_path_buf();
        std::fs::write(&path, [0xff, 0xfe]).expect("write bytes");
        let path_str = path.to_str().expect("utf-8 path").to_string();
        let tagged = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("file"),
            value: Value::String(path_str.clone()),
        }));
        let err = expand_scenario(tagged).expect_err("must error");
        let msg = format!("{err}");
        assert!(msg.contains(&path_str), "msg: {msg}");
    }
}
