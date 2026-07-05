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
impl std::ops::Deref for Community {
    type Target = str;
    fn deref(&self) -> &str {
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
#[derive(Clone, Default, serde::Deserialize)]
#[serde(transparent)]
pub struct Password(pub String);

#[cfg(feature = "snmp")]
impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted:{}>", short_hash(&self.0))
    }
}

#[cfg(feature = "snmp")]
impl std::ops::Deref for Password {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

// Distinct-per-value redacted marker: credential rotation must change `source_config_hash`.
#[cfg(feature = "snmp")]
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
    fn password_default_is_empty() {
        let p = Password::default();
        assert!(p.is_empty());
    }

    #[test]
    fn short_hash_of_empty_string_is_stable() {
        // sha256("") = e3b0c442... — first 8 hex chars are "e3b0c442"
        assert_eq!(short_hash(""), "e3b0c442");
    }
}
