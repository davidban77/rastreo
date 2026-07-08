use crate::prober::redacted::Password;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct UsmCredentials {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub auth: UsmAuth,
    #[serde(default)]
    pub privacy: UsmPrivacy,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(tag = "algorithm", rename_all = "snake_case")]
pub enum UsmAuth {
    #[default]
    None,
    Md5 {
        password: Password,
    },
    Sha1 {
        password: Password,
    },
    Sha224 {
        password: Password,
    },
    Sha256 {
        password: Password,
    },
    Sha384 {
        password: Password,
    },
    Sha512 {
        password: Password,
    },
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(tag = "algorithm", rename_all = "snake_case")]
pub enum UsmPrivacy {
    #[default]
    None,
    Des {
        password: Password,
    },
    Aes128 {
        password: Password,
    },
    Aes192 {
        password: Password,
    },
    Aes256 {
        password: Password,
    },
}

/// Standardized USM auth algorithms per RFC 3414 (MD5, SHA-1) and RFC 7860 (SHA-2 family).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthAlgo {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl AuthAlgo {
    /// Length of the localized key in bytes — the hash's output size.
    pub fn key_len(self) -> usize {
        match self {
            AuthAlgo::Md5 => 16,
            AuthAlgo::Sha1 => 20,
            AuthAlgo::Sha224 => 28,
            AuthAlgo::Sha256 => 32,
            AuthAlgo::Sha384 => 48,
            AuthAlgo::Sha512 => 64,
        }
    }

    /// Truncated HMAC output length per RFC 3414 §6.3.1 and RFC 7860 §4.2.
    pub fn hmac_trunc_len(self) -> usize {
        match self {
            AuthAlgo::Md5 => 12,
            AuthAlgo::Sha1 => 12,
            AuthAlgo::Sha224 => 16,
            AuthAlgo::Sha256 => 24,
            AuthAlgo::Sha384 => 32,
            AuthAlgo::Sha512 => 48,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivAlgo {
    Des,
    Aes128,
    Aes192,
    Aes256,
}

impl PrivAlgo {
    /// Encryption key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            PrivAlgo::Des => 16,
            PrivAlgo::Aes128 => 16,
            PrivAlgo::Aes192 => 24,
            PrivAlgo::Aes256 => 32,
        }
    }
}

/// Security level derived from an (auth, privacy) pair per RFC 3411.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    NoAuthNoPriv,
    AuthNoPriv,
    AuthPriv,
}

impl SecurityLevel {
    /// msgFlags security bits: bit 0 = auth, bit 1 = priv.
    pub fn flag_bits(self) -> u8 {
        match self {
            SecurityLevel::NoAuthNoPriv => 0b00,
            SecurityLevel::AuthNoPriv => 0b01,
            SecurityLevel::AuthPriv => 0b11,
        }
    }
}

pub(crate) enum ResolvedAuth {
    None,
    Some { algo: AuthAlgo, password: String },
}

pub(crate) enum ResolvedPriv {
    None,
    Some { algo: PrivAlgo, password: String },
}

impl UsmAuth {
    pub fn password(&self) -> Option<&Password> {
        match self {
            UsmAuth::None => None,
            UsmAuth::Md5 { password }
            | UsmAuth::Sha1 { password }
            | UsmAuth::Sha224 { password }
            | UsmAuth::Sha256 { password }
            | UsmAuth::Sha384 { password }
            | UsmAuth::Sha512 { password } => Some(password),
        }
    }

    pub(crate) fn resolve(&self) -> ResolvedAuth {
        match self {
            UsmAuth::None => ResolvedAuth::None,
            UsmAuth::Md5 { password } => ResolvedAuth::Some {
                algo: AuthAlgo::Md5,
                password: password.0.clone(),
            },
            UsmAuth::Sha1 { password } => ResolvedAuth::Some {
                algo: AuthAlgo::Sha1,
                password: password.0.clone(),
            },
            UsmAuth::Sha224 { password } => ResolvedAuth::Some {
                algo: AuthAlgo::Sha224,
                password: password.0.clone(),
            },
            UsmAuth::Sha256 { password } => ResolvedAuth::Some {
                algo: AuthAlgo::Sha256,
                password: password.0.clone(),
            },
            UsmAuth::Sha384 { password } => ResolvedAuth::Some {
                algo: AuthAlgo::Sha384,
                password: password.0.clone(),
            },
            UsmAuth::Sha512 { password } => ResolvedAuth::Some {
                algo: AuthAlgo::Sha512,
                password: password.0.clone(),
            },
        }
    }
}

impl UsmPrivacy {
    pub fn password(&self) -> Option<&Password> {
        match self {
            UsmPrivacy::None => None,
            UsmPrivacy::Des { password }
            | UsmPrivacy::Aes128 { password }
            | UsmPrivacy::Aes192 { password }
            | UsmPrivacy::Aes256 { password } => Some(password),
        }
    }

    pub(crate) fn resolve(&self) -> ResolvedPriv {
        match self {
            UsmPrivacy::None => ResolvedPriv::None,
            UsmPrivacy::Des { password } => ResolvedPriv::Some {
                algo: PrivAlgo::Des,
                password: password.0.clone(),
            },
            UsmPrivacy::Aes128 { password } => ResolvedPriv::Some {
                algo: PrivAlgo::Aes128,
                password: password.0.clone(),
            },
            UsmPrivacy::Aes192 { password } => ResolvedPriv::Some {
                algo: PrivAlgo::Aes192,
                password: password.0.clone(),
            },
            UsmPrivacy::Aes256 { password } => ResolvedPriv::Some {
                algo: PrivAlgo::Aes256,
                password: password.0.clone(),
            },
        }
    }
}

pub(crate) fn derive_security_level(
    auth: &ResolvedAuth,
    privacy: &ResolvedPriv,
) -> Result<SecurityLevel, &'static str> {
    match (auth, privacy) {
        (ResolvedAuth::None, ResolvedPriv::None) => Ok(SecurityLevel::NoAuthNoPriv),
        (ResolvedAuth::Some { .. }, ResolvedPriv::None) => Ok(SecurityLevel::AuthNoPriv),
        (ResolvedAuth::Some { .. }, ResolvedPriv::Some { .. }) => Ok(SecurityLevel::AuthPriv),
        (ResolvedAuth::None, ResolvedPriv::Some { .. }) => {
            Err("snmp v3 privacy requires an auth algorithm")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usm_credentials_default_is_no_auth_no_priv() {
        let c = UsmCredentials::default();
        assert!(c.username.is_empty());
        assert!(matches!(c.auth, UsmAuth::None));
        assert!(matches!(c.privacy, UsmPrivacy::None));
    }

    #[test]
    fn security_level_derivation_from_auth_privacy_pair() {
        let none = ResolvedAuth::None;
        let auth = ResolvedAuth::Some {
            algo: AuthAlgo::Sha256,
            password: "p".into(),
        };
        let no_priv = ResolvedPriv::None;
        let priv_ = ResolvedPriv::Some {
            algo: PrivAlgo::Aes128,
            password: "p".into(),
        };
        assert_eq!(
            derive_security_level(&none, &no_priv).expect("noAuthNoPriv"),
            SecurityLevel::NoAuthNoPriv
        );
        assert_eq!(
            derive_security_level(&auth, &no_priv).expect("authNoPriv"),
            SecurityLevel::AuthNoPriv
        );
        assert_eq!(
            derive_security_level(&auth, &priv_).expect("authPriv"),
            SecurityLevel::AuthPriv
        );
        assert!(derive_security_level(&none, &priv_).is_err());
    }

    #[test]
    fn security_level_flag_bits_match_rfc_3412() {
        assert_eq!(SecurityLevel::NoAuthNoPriv.flag_bits(), 0b00);
        assert_eq!(SecurityLevel::AuthNoPriv.flag_bits(), 0b01);
        assert_eq!(SecurityLevel::AuthPriv.flag_bits(), 0b11);
    }

    #[test]
    fn auth_algo_key_and_hmac_lengths_match_rfcs() {
        assert_eq!(
            (AuthAlgo::Md5.key_len(), AuthAlgo::Md5.hmac_trunc_len()),
            (16, 12)
        );
        assert_eq!(
            (AuthAlgo::Sha1.key_len(), AuthAlgo::Sha1.hmac_trunc_len()),
            (20, 12)
        );
        assert_eq!(
            (
                AuthAlgo::Sha224.key_len(),
                AuthAlgo::Sha224.hmac_trunc_len()
            ),
            (28, 16)
        );
        assert_eq!(
            (
                AuthAlgo::Sha256.key_len(),
                AuthAlgo::Sha256.hmac_trunc_len()
            ),
            (32, 24)
        );
        assert_eq!(
            (
                AuthAlgo::Sha384.key_len(),
                AuthAlgo::Sha384.hmac_trunc_len()
            ),
            (48, 32)
        );
        assert_eq!(
            (
                AuthAlgo::Sha512.key_len(),
                AuthAlgo::Sha512.hmac_trunc_len()
            ),
            (64, 48)
        );
    }

    #[test]
    fn priv_algo_key_lengths_match_specs() {
        assert_eq!(PrivAlgo::Des.key_len(), 16);
        assert_eq!(PrivAlgo::Aes128.key_len(), 16);
        assert_eq!(PrivAlgo::Aes192.key_len(), 24);
        assert_eq!(PrivAlgo::Aes256.key_len(), 32);
    }

    #[cfg(feature = "config")]
    #[rstest::rstest]
    #[case("md5")]
    #[case("sha1")]
    #[case("sha224")]
    #[case("sha256")]
    #[case("sha384")]
    #[case("sha512")]
    fn usm_auth_deserializes_all_algorithms(#[case] name: &str) {
        let yaml = format!("algorithm: {name}\npassword: secret\n");
        let auth: UsmAuth = serde_yaml_ng::from_str(&yaml).expect("deserialize");
        assert!(!matches!(auth, UsmAuth::None));
    }

    #[cfg(feature = "config")]
    #[test]
    fn usm_auth_deserializes_sha256_variant() {
        let auth: UsmAuth =
            serde_yaml_ng::from_str("algorithm: sha256\npassword: secret\n").expect("deserialize");
        match auth {
            UsmAuth::Sha256 { password } => assert_eq!(&*password, "secret"),
            other => panic!("expected Sha256, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn usm_privacy_deserializes_aes128_variant() {
        let priv_: UsmPrivacy =
            serde_yaml_ng::from_str("algorithm: aes128\npassword: secret\n").expect("deserialize");
        match priv_ {
            UsmPrivacy::Aes128 { password } => assert_eq!(&*password, "secret"),
            other => panic!("expected Aes128, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn usm_credentials_deserializes_full_shape_from_yaml() {
        let yaml = "username: probe\nauth:\n  algorithm: sha256\n  password: authpw\nprivacy:\n  algorithm: aes128\n  password: privpw\n";
        let c: UsmCredentials = serde_yaml_ng::from_str(yaml).expect("deserialize");
        assert_eq!(c.username, "probe");
        assert!(matches!(c.auth, UsmAuth::Sha256 { .. }));
        assert!(matches!(c.privacy, UsmPrivacy::Aes128 { .. }));
    }

    #[cfg(feature = "config")]
    #[test]
    fn usm_credentials_deserializes_missing_auth_privacy_as_none() {
        let yaml = "username: probe\n";
        let c: UsmCredentials = serde_yaml_ng::from_str(yaml).expect("deserialize");
        assert!(matches!(c.auth, UsmAuth::None));
        assert!(matches!(c.privacy, UsmPrivacy::None));
    }
}
