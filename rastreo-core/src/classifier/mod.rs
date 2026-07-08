use crate::error::RastreoError;
use crate::model::device::DeviceRecord;

/// Assigns canonical `platform` / `role` values on a `DeviceRecord` based on the signals fused into it.
///
/// Runs after per-IP fusion and identity correlation, before `scan_metadata` stamping and encoding.
/// Implementations mutate the record in place. The classifier sees the fully-fused record but does
/// not see `scan_metadata` — classifiers must not depend on scan-level metadata.
pub trait Classifier: Send + Sync {
    fn classify(&self, record: &mut DeviceRecord) -> Result<(), RastreoError>;
}

/// Default classifier that leaves every record untouched. Used when no classifier is configured.
pub struct NoopClassifier;

impl Classifier for NoopClassifier {
    fn classify(&self, _record: &mut DeviceRecord) -> Result<(), RastreoError> {
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ClassifierConfig {
    Noop,
}

pub fn create_classifier(config: &ClassifierConfig) -> Result<Box<dyn Classifier>, RastreoError> {
    match config {
        ClassifierConfig::Noop => Ok(Box::new(NoopClassifier)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    use crate::model::device::{
        Confidence, IdentityKey, CURRENT_SCHEMA_ID, CURRENT_SCHEMA_VERSION,
    };
    use crate::model::scan::ScanMetadata;

    fn empty_record() -> DeviceRecord {
        DeviceRecord {
            identity_key: IdentityKey::new("ip:10.0.0.1").expect("identity"),
            mgmt_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            mac: None,
            manufacturer: None,
            platform: None,
            role: None,
            confidence: Confidence::new(0.1).expect("confidence"),
            last_seen: SystemTime::UNIX_EPOCH,
            signals: Vec::new(),
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
            schema_id: CURRENT_SCHEMA_ID.to_string(),
            alt_ips: Vec::new(),
            possible_alias_of: None,
            scan_metadata: ScanMetadata::default(),
        }
    }

    #[test]
    fn noop_classifier_leaves_record_unchanged() {
        let mut record = empty_record();
        let before = record.clone();
        NoopClassifier
            .classify(&mut record)
            .expect("noop is infallible");
        assert!(record.platform.is_none());
        assert!(record.role.is_none());
        assert_eq!(record.identity_key.as_str(), before.identity_key.as_str());
        assert_eq!(record.mgmt_ip, before.mgmt_ip);
        assert_eq!(record.confidence.value(), before.confidence.value());
        assert_eq!(record.signals.len(), before.signals.len());
    }

    #[test]
    fn noop_classifier_does_not_overwrite_prepopulated_platform_or_role() {
        let mut record = empty_record();
        record.platform = Some("cisco_ios".into());
        record.role = Some("router".into());
        NoopClassifier
            .classify(&mut record)
            .expect("noop is infallible");
        assert_eq!(record.platform.as_deref(), Some("cisco_ios"));
        assert_eq!(record.role.as_deref(), Some("router"));
    }

    #[test]
    fn create_classifier_produces_noop_for_noop_config() {
        let c = create_classifier(&ClassifierConfig::Noop).expect("create");
        let mut record = empty_record();
        c.classify(&mut record).expect("noop is infallible");
        assert!(record.platform.is_none());
        assert!(record.role.is_none());
    }

    #[cfg(feature = "config")]
    #[test]
    fn classifier_config_deserializes_noop_from_yaml() {
        let yaml = "type: noop\n";
        let cfg: ClassifierConfig = serde_yaml_ng::from_str(yaml).expect("deserialize");
        assert!(matches!(cfg, ClassifierConfig::Noop));
    }

    #[test]
    fn classifier_config_deserializes_noop_from_json() {
        let json = r#"{"type":"noop"}"#;
        let cfg: ClassifierConfig = serde_json::from_str(json).expect("deserialize");
        assert!(matches!(cfg, ClassifierConfig::Noop));
    }

    #[test]
    fn classifier_config_serializes_noop_with_type_tag() {
        let json = serde_json::to_value(ClassifierConfig::Noop).expect("serialize");
        assert_eq!(json["type"], "noop");
    }

    #[test]
    fn classifier_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<NoopClassifier>();
        assert_send_sync::<dyn Classifier>();
        assert_send_sync::<Box<dyn Classifier>>();
        assert_send_sync::<ClassifierConfig>();
    }
}
