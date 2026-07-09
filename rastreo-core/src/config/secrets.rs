use serde_yaml_ng::Value;

use crate::error::ConfigError;

/// Recursively expand `${VAR}` env-var references in string scalars and read `!file <path>` tagged scalars into their file contents. YAML mapping keys are left unmodified.
pub(crate) fn expand(value: Value) -> Result<Value, ConfigError> {
    match value {
        Value::String(s) => Ok(Value::String(interpolate_env(&s)?)),
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
                let inner = expand(tagged.value)?;
                Ok(Value::Tagged(Box::new(serde_yaml_ng::value::TaggedValue {
                    tag: tagged.tag,
                    value: inner,
                })))
            }
        }
        Value::Sequence(seq) => {
            let mut out = Vec::with_capacity(seq.len());
            for item in seq {
                out.push(expand(item)?);
            }
            Ok(Value::Sequence(out))
        }
        Value::Mapping(mut map) => {
            for (_key, v) in map.iter_mut() {
                // On error, this leaves `Null` in place of one value; caller must drop the
                // partially-transformed tree.
                let taken = std::mem::replace(v, Value::Null);
                *v = expand(taken)?;
            }
            Ok(Value::Mapping(map))
        }
        other => Ok(other),
    }
}

fn interpolate_env(input: &str) -> Result<String, ConfigError> {
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
                            "environment variable {name} referenced in scenario is not set"
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

    #[test]
    fn expand_replaces_single_env_var() {
        set_var("RASTREO_TEST_SECRETS_SINGLE", "bar");
        let out = expand(Value::String("${RASTREO_TEST_SECRETS_SINGLE}".into())).expect("expand");
        assert_eq!(out, Value::String("bar".into()));
        remove_var("RASTREO_TEST_SECRETS_SINGLE");
    }

    #[test]
    fn expand_replaces_multiple_env_vars_in_one_string() {
        set_var("RASTREO_TEST_SECRETS_MULTI_A", "foo");
        set_var("RASTREO_TEST_SECRETS_MULTI_B", "bar");
        let out = expand(Value::String(
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
        let out = expand(Value::String(
            "prefix-${RASTREO_TEST_SECRETS_SURROUND}-suffix".into(),
        ))
        .expect("expand");
        assert_eq!(out, Value::String("prefix-middle-suffix".into()));
        remove_var("RASTREO_TEST_SECRETS_SURROUND");
    }

    #[test]
    fn expand_missing_env_var_returns_actionable_error() {
        remove_var("RASTREO_TEST_SECRETS_MISSING_XYZ");
        let err = expand(Value::String("${RASTREO_TEST_SECRETS_MISSING_XYZ}".into()))
            .expect_err("must error");
        let msg = format!("{err}");
        assert!(
            msg.contains("RASTREO_TEST_SECRETS_MISSING_XYZ"),
            "msg: {msg}"
        );
        assert!(msg.contains("not set"), "msg: {msg}");
    }

    #[test]
    fn expand_empty_env_var_substitutes_as_empty_string() {
        set_var("RASTREO_TEST_SECRETS_EMPTY", "");
        let out = expand(Value::String(
            "prefix-${RASTREO_TEST_SECRETS_EMPTY}-suffix".into(),
        ))
        .expect("expand");
        assert_eq!(out, Value::String("prefix--suffix".into()));
        remove_var("RASTREO_TEST_SECRETS_EMPTY");
    }

    #[test]
    fn expand_escape_sequence_preserves_literal() {
        set_var("RASTREO_TEST_SECRETS_ESCAPE", "should-not-be-used");
        let out = expand(Value::String("$${RASTREO_TEST_SECRETS_ESCAPE}".into())).expect("expand");
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
        let out = expand(raw).expect("expand");
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
        let out = expand(Value::Mapping(map)).expect("expand");
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
        assert_eq!(expand(Value::Bool(true)).expect("bool"), Value::Bool(true));
        assert_eq!(expand(Value::Null).expect("null"), Value::Null);
        let n = Value::Number(serde_yaml_ng::Number::from(42u64));
        assert_eq!(expand(n.clone()).expect("num"), n);
    }

    #[test]
    fn expand_identifier_pattern_rejects_bare_dollar_brace() {
        let out = expand(Value::String("${".into())).expect("expand");
        assert_eq!(out, Value::String("${".into()));
        let out = expand(Value::String("${1foo}".into())).expect("expand");
        assert_eq!(out, Value::String("${1foo}".into()));
        let out = expand(Value::String("${a-b}".into())).expect("expand");
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
        let out = expand(tagged).expect("expand");
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
        let out = expand(tagged).expect("expand");
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
        let out = expand(tagged).expect("expand");
        assert_eq!(out, Value::String("  secret".into()));
    }

    #[test]
    fn expand_file_tag_missing_file_returns_actionable_error() {
        let tagged = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("file"),
            value: Value::String("/nonexistent/rastreo/test/path/xyzzy".into()),
        }));
        let err = expand(tagged).expect_err("must error");
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
        let out = expand(raw).expect("expand");
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
        let err = expand(tagged).expect_err("must error");
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
        let out = expand(tagged).expect("expand");
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
        let out =
            expand(Value::String("café-${RASTREO_TEST_SECRETS_UTF8}".into())).expect("expand");
        assert_eq!(out, Value::String("café-x".into()));
        remove_var("RASTREO_TEST_SECRETS_UTF8");
    }

    #[test]
    fn expand_preserves_unicode_string_with_no_interpolation() {
        let out = expand(Value::String("naïve".into())).expect("expand");
        assert_eq!(out, Value::String("naïve".into()));
    }

    #[test]
    fn expand_recurses_into_unknown_tag_body() {
        set_var("RASTREO_TEST_SECRETS_TAGGED", "value");
        let tagged = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("Custom"),
            value: Value::String("prefix-${RASTREO_TEST_SECRETS_TAGGED}-suffix".into()),
        }));
        let out = expand(tagged).expect("expand");
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
    fn expand_file_tag_non_utf8_contents_returns_error_naming_path() {
        let f = NamedTempFile::new().expect("tempfile");
        let path = f.path().to_path_buf();
        std::fs::write(&path, [0xff, 0xfe]).expect("write bytes");
        let path_str = path.to_str().expect("utf-8 path").to_string();
        let tagged = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("file"),
            value: Value::String(path_str.clone()),
        }));
        let err = expand(tagged).expect_err("must error");
        let msg = format!("{err}");
        assert!(msg.contains(&path_str), "msg: {msg}");
    }
}
