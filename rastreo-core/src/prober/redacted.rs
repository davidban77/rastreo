#[cfg(feature = "snmp")]
#[derive(Clone, serde::Deserialize)]
#[serde(transparent)]
pub struct Community(pub String);

#[cfg(feature = "snmp")]
impl std::fmt::Debug for Community {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
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
        f.write_str("<redacted>")
    }
}

#[cfg(feature = "snmp")]
impl std::ops::Deref for Password {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

#[cfg(all(test, feature = "snmp"))]
mod tests {
    use super::*;

    #[test]
    fn community_debug_is_redacted() {
        let c = Community("supersecret".to_string());
        assert_eq!(format!("{c:?}"), "<redacted>");
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
        assert_eq!(format!("{p:?}"), "<redacted>");
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
}
