#[cfg(feature = "snmp")]
#[derive(Clone, serde::Deserialize)]
#[serde(transparent)]
pub struct Community(pub String);

#[cfg(feature = "snmp")]
impl std::fmt::Debug for Community {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted:{}>", short_hash(&self.0))
    }
}

#[cfg(feature = "snmp")]
impl serde::Serialize for Community {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&format_args!("<redacted:{}>", short_hash(&self.0)))
    }
}

#[cfg(feature = "snmp")]
impl std::ops::Deref for Community {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "snmp")]
impl Community {
    /// Returns the underlying community string. Callers must not log, serialize, or persist the result.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "snmp")]
impl From<Community> for String {
    fn from(c: Community) -> String {
        c.0
    }
}

#[cfg(feature = "snmp")]
impl schemars::JsonSchema for Community {
    // Wire form is a plain YAML string; the redacted `<redacted:HHHHHHHH>` shape only affects Serialize output.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Community".into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "SNMP community string written verbatim in YAML; serialized as `<redacted:HHHHHHHH>` to keep the plaintext out of logs and NDJSON output.",
        })
    }
}

#[cfg(any(
    feature = "snmp",
    feature = "nats",
    feature = "kafka",
    feature = "gnmi"
))]
#[derive(Clone, Default, serde::Deserialize)]
#[serde(transparent)]
pub struct Password(pub String);

#[cfg(any(
    feature = "snmp",
    feature = "nats",
    feature = "kafka",
    feature = "gnmi"
))]
impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted:{}>", short_hash(&self.0))
    }
}

#[cfg(any(
    feature = "snmp",
    feature = "nats",
    feature = "kafka",
    feature = "gnmi"
))]
impl serde::Serialize for Password {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&format_args!("<redacted:{}>", short_hash(&self.0)))
    }
}

#[cfg(any(
    feature = "snmp",
    feature = "nats",
    feature = "kafka",
    feature = "gnmi"
))]
impl std::ops::Deref for Password {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

#[cfg(any(
    feature = "snmp",
    feature = "nats",
    feature = "kafka",
    feature = "gnmi"
))]
impl Password {
    /// Returns the underlying secret string. Callers must not log, serialize, or persist the result.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

#[cfg(any(
    feature = "snmp",
    feature = "nats",
    feature = "kafka",
    feature = "gnmi"
))]
impl schemars::JsonSchema for Password {
    // Wire form is a plain YAML string; the redacted `<redacted:HHHHHHHH>` shape only affects Serialize output.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Password".into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Credential value written verbatim in YAML; serialized as `<redacted:HHHHHHHH>` to keep the plaintext out of logs and NDJSON output.",
        })
    }
}

// Distinct-per-value redacted marker: credential rotation must change `source_config_hash`.
#[cfg(any(
    feature = "snmp",
    feature = "nats",
    feature = "kafka",
    feature = "gnmi"
))]
fn short_hash(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    let bytes = &digest[..4];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(all(test, feature = "snmp"))]
mod tests {
    use super::*;

    #[test]
    fn community_debug_is_redacted() {
        let c = Community("supersecret".to_string());
        let s = format!("{c:?}");
        assert!(s.starts_with("<redacted:"), "got: {s}");
        assert!(s.ends_with('>'), "got: {s}");
        assert!(!s.contains("supersecret"), "plaintext leaked: {s}");
    }

    #[test]
    fn community_debug_is_distinct_per_value() {
        let a = format!("{:?}", Community("public".to_string()));
        let b = format!("{:?}", Community("prod-r0".to_string()));
        assert_ne!(
            a, b,
            "different secrets must produce different Debug output"
        );
    }

    #[test]
    fn community_debug_is_stable_for_same_value() {
        let a = format!("{:?}", Community("public".to_string()));
        let b = format!("{:?}", Community("public".to_string()));
        assert_eq!(a, b);
    }

    #[test]
    fn community_deserializes_transparently_from_string() {
        let c: Community = serde_json::from_str("\"public\"").expect("deserialize");
        assert_eq!(&*c, "public");
    }

    #[test]
    fn community_deref_exposes_str() {
        let c = Community("readonly".to_string());
        assert_eq!(&*c, "readonly");
    }

    #[test]
    fn community_expose_returns_inner() {
        let c = Community("readonly".to_string());
        assert_eq!(c.expose(), "readonly");
    }

    #[test]
    fn community_into_string_returns_inner() {
        let c = Community("public".to_string());
        let s: String = c.into();
        assert_eq!(s, "public");
    }

    #[test]
    fn password_debug_is_redacted() {
        let p = Password("maplesyrup".to_string());
        let s = format!("{p:?}");
        assert!(s.starts_with("<redacted:"), "got: {s}");
        assert!(s.ends_with('>'), "got: {s}");
        assert!(!s.contains("maplesyrup"), "plaintext leaked: {s}");
    }

    #[test]
    fn password_debug_is_distinct_per_value() {
        let a = format!("{:?}", Password("authpass".to_string()));
        let b = format!("{:?}", Password("privpass".to_string()));
        assert_ne!(a, b);
    }

    #[test]
    fn password_deserializes_transparently_from_string() {
        let p: Password = serde_json::from_str("\"authpass\"").expect("deserialize");
        assert_eq!(&*p, "authpass");
    }

    #[test]
    fn password_deref_exposes_str() {
        let p = Password("privpass".to_string());
        assert_eq!(&*p, "privpass");
    }

    #[test]
    fn password_expose_returns_inner() {
        let p = Password("privpass".to_string());
        assert_eq!(p.expose(), "privpass");
    }

    #[test]
    fn password_default_is_empty() {
        let p = Password::default();
        assert!(p.is_empty());
    }

    #[test]
    fn community_json_schema_is_string_with_description() {
        let schema = schemars::schema_for!(Community);
        let json = serde_json::to_value(&schema).expect("schema serializes");
        assert_eq!(json["type"], "string");
        assert!(
            json["description"]
                .as_str()
                .is_some_and(|d| d.contains("community")),
            "expected community description, got {:?}",
            json["description"]
        );
    }

    #[test]
    fn password_json_schema_is_string_with_description() {
        let schema = schemars::schema_for!(Password);
        let json = serde_json::to_value(&schema).expect("schema serializes");
        assert_eq!(json["type"], "string");
        assert!(
            json["description"]
                .as_str()
                .is_some_and(|d| d.contains("Credential")),
            "expected credential description, got {:?}",
            json["description"]
        );
    }

    #[test]
    fn short_hash_of_empty_string_is_stable() {
        // sha256("") = e3b0c442... — first 8 hex chars are "e3b0c442"
        assert_eq!(short_hash(""), "e3b0c442");
    }

    #[test]
    fn community_serialize_is_redacted() {
        let c = Community("supersecret".to_string());
        let json = serde_json::to_string(&c).expect("serialize");
        assert!(!json.contains("supersecret"), "plaintext leaked: {json}");
        assert_eq!(json, format!("\"{:?}\"", c));
    }

    #[test]
    fn community_serialize_is_distinct_per_value() {
        let a = serde_json::to_string(&Community("public".to_string())).expect("serialize a");
        let b = serde_json::to_string(&Community("prod-r0".to_string())).expect("serialize b");
        assert_ne!(a, b, "different secrets must serialize distinctly");
    }

    #[test]
    fn password_serialize_is_redacted() {
        let p = Password("maplesyrup".to_string());
        let json = serde_json::to_string(&p).expect("serialize");
        assert!(!json.contains("maplesyrup"), "plaintext leaked: {json}");
        assert_eq!(json, format!("\"{:?}\"", p));
    }

    #[test]
    fn password_serialize_is_distinct_per_value() {
        let a = serde_json::to_string(&Password("authpass".to_string())).expect("serialize a");
        let b = serde_json::to_string(&Password("privpass".to_string())).expect("serialize b");
        assert_ne!(a, b);
    }
}

#[cfg(all(test, feature = "nats", not(feature = "snmp")))]
mod nats_only_tests {
    use super::*;

    #[test]
    fn password_debug_is_redacted() {
        let p = Password("maplesyrup".to_string());
        let s = format!("{p:?}");
        assert!(s.starts_with("<redacted:"), "got: {s}");
        assert!(s.ends_with('>'), "got: {s}");
        assert!(!s.contains("maplesyrup"), "plaintext leaked: {s}");
    }

    #[test]
    fn password_expose_returns_inner() {
        let p = Password("privpass".to_string());
        assert_eq!(p.expose(), "privpass");
    }

    #[test]
    fn password_serialize_is_redacted() {
        let p = Password("maplesyrup".to_string());
        let json = serde_json::to_string(&p).expect("serialize");
        assert!(!json.contains("maplesyrup"), "plaintext leaked: {json}");
    }
}
