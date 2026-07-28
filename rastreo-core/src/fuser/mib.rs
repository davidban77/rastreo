use std::collections::HashMap;
use std::io::BufRead;

use crate::error::{ConfigError, RastreoError};
use crate::fuser::Fuser;
use crate::model::device::DeviceRecord;
use crate::model::outcome::{ProbeOutcome, Signal};

const BUNDLED: &[u8] = include_bytes!("../../data/mib_identity.gz");

#[cfg(test)]
const MAX_BUNDLED_MIB_ENTRIES: usize = 300;

pub struct MibEnrichmentFuser {
    inner: Box<dyn Fuser>,
    table: MibTable,
}

impl MibEnrichmentFuser {
    pub fn new(inner: Box<dyn Fuser>, table: MibTable) -> Self {
        Self { inner, table }
    }

    fn enrich(&self, record: &mut DeviceRecord) {
        let entry = {
            let Some(oid) = record.signals.iter().find_map(|s| match s {
                Signal::SnmpSysObjectId(oid) => Some(oid.as_str()),
                _ => None,
            }) else {
                return;
            };
            match self.table.lookup(oid) {
                Some(entry) => entry,
                None => return,
            }
        };

        if let Some(model) = &entry.model {
            record.model = Some(model.clone());
        }
        if let Some(product_family) = &entry.product_family {
            record.product_family = Some(product_family.clone());
        }
        if record.manufacturer.is_none() {
            if let Some(manufacturer) = &entry.manufacturer {
                record.manufacturer = Some(manufacturer.clone());
            }
        }
    }
}

impl Fuser for MibEnrichmentFuser {
    fn ingest(&mut self, outcomes: Vec<ProbeOutcome>) -> Result<Vec<DeviceRecord>, RastreoError> {
        let mut records = self.inner.ingest(outcomes)?;
        for record in &mut records {
            self.enrich(record);
        }
        Ok(records)
    }

    fn finish(&mut self) -> Result<Vec<DeviceRecord>, RastreoError> {
        let mut records = self.inner.finish()?;
        for record in &mut records {
            self.enrich(record);
        }
        Ok(records)
    }
}

pub struct MibEntry {
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub product_family: Option<String>,
}

pub struct MibTable(HashMap<String, MibEntry>);

impl MibTable {
    pub fn from_bundled() -> Result<Self, RastreoError> {
        use flate2::read::GzDecoder;
        let decoder = GzDecoder::new(BUNDLED);
        let reader = std::io::BufReader::new(decoder);
        parse_mib(reader).map_err(|e| match e {
            ParseError::Line { line, message } => RastreoError::Config(ConfigError::invalid(
                format!("failed to parse bundled MIB identity table: line {line}: {message}"),
            )),
            ParseError::Io(msg) => RastreoError::Config(ConfigError::invalid(format!(
                "failed to read bundled MIB identity table: {msg}"
            ))),
        })
    }

    pub fn from_path(path: &str) -> Result<Self, RastreoError> {
        // Overlay MERGES onto the bundled seed (user keys win) — the bundled table is a stub, not
        // a comprehensive database like OUI's manuf snapshot, so a user file extends rather than replaces.
        let mut table = Self::from_bundled()?;
        let file = std::fs::File::open(path).map_err(|e| {
            RastreoError::Config(ConfigError::invalid(format!(
                "MIB data file '{path}' could not be opened: {e}"
            )))
        })?;
        let reader = std::io::BufReader::new(file);
        let overlay = parse_mib(reader).map_err(|e| match e {
            ParseError::Line { line, message } => {
                RastreoError::Config(ConfigError::invalid(format!(
                    "MIB data file '{path}' is not a valid mib-identity file: line {line}: {message}"
                )))
            }
            ParseError::Io(msg) => RastreoError::Config(ConfigError::invalid(format!(
                "MIB data file '{path}' could not be read: {msg}"
            ))),
        })?;
        table.0.extend(overlay.0);
        Ok(table)
    }

    pub fn lookup(&self, oid: &str) -> Option<&MibEntry> {
        self.0.get(oid)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Debug)]
enum ParseError {
    Line { line: usize, message: String },
    Io(String),
}

fn parse_mib<R: BufRead>(reader: R) -> Result<MibTable, ParseError> {
    let mut entries: HashMap<String, MibEntry> = HashMap::new();

    for (line_no_zero, raw) in reader.lines().enumerate() {
        let line_no = line_no_zero + 1;
        let raw = raw.map_err(|e| ParseError::Io(e.to_string()))?;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let cols: Vec<&str> = trimmed.split('\t').collect();
        if cols.len() != 4 {
            return Err(ParseError::Line {
                line: line_no,
                message: format!(
                    "expected 4 tab-separated columns (sys_object_id, manufacturer, model, product_family), found {}",
                    cols.len()
                ),
            });
        }

        let oid = cols[0].trim();
        if !crate::oid::is_dotted_decimal(oid) {
            return Err(ParseError::Line {
                line: line_no,
                message: format!(
                    "sys_object_id '{oid}' must be dotted-decimal with no leading dot and no whitespace"
                ),
            });
        }

        let manufacturer = cols[1].trim();
        let model = cols[2].trim();
        let product_family = cols[3].trim();
        // An empty column is "no value"; a row with no identity column teaches nothing.
        if manufacturer.is_empty() && model.is_empty() && product_family.is_empty() {
            return Err(ParseError::Line {
                line: line_no,
                message: "at least one of manufacturer, model, product_family must be set".into(),
            });
        }

        entries.insert(
            oid.to_string(),
            MibEntry {
                manufacturer: (!manufacturer.is_empty()).then(|| manufacturer.to_string()),
                model: (!model.is_empty()).then(|| model.to_string()),
                product_family: (!product_family.is_empty()).then(|| product_family.to_string()),
            },
        );
    }

    Ok(MibTable(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    use crate::fuser::DirectFuser;
    use crate::model::device::{
        Confidence, IdentityKey, CURRENT_SCHEMA_ID, CURRENT_SCHEMA_VERSION,
    };
    use crate::model::outcome::ProbeKind;
    use crate::model::scan::ScanMetadata;
    use std::sync::Arc;

    const SRLINUX_OID: &str = "1.3.6.1.4.1.6527.1.20.26";
    const NETSNMP_LINUX_OID: &str = "1.3.6.1.4.1.8072.3.2.10";

    fn parse_str(input: &str) -> MibTable {
        parse_mib(Cursor::new(input)).expect("parse ok")
    }

    // Mirrors prober::snmp::oid_to_dotted (feature-gated + module-private, so replicated here):
    // arcs joined by '.', no leading dot.
    fn arcs_to_dotted(arcs: &[u32]) -> String {
        let mut out = String::new();
        for (i, arc) in arcs.iter().enumerate() {
            if i > 0 {
                out.push('.');
            }
            out.push_str(&arc.to_string());
        }
        out
    }

    fn record_with(oid: Option<&str>, manufacturer: Option<&str>) -> DeviceRecord {
        let signals = match oid {
            Some(o) => vec![Signal::SnmpSysObjectId(o.to_string())],
            None => vec![Signal::OpenPort(161)],
        };
        DeviceRecord {
            identity_key: IdentityKey::new("ip:10.0.0.1").expect("identity"),
            mgmt_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            mac: None,
            manufacturer: manufacturer.map(str::to_string),
            model: None,
            product_family: None,
            platform: None,
            os_version: None,
            ssh_version: None,
            http_server: None,
            http_version: None,
            role: None,
            confidence: Confidence::new(0.1).expect("confidence"),
            last_seen: SystemTime::UNIX_EPOCH,
            signals,
            probe_kinds: Vec::new(),
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
            schema_id: CURRENT_SCHEMA_ID.to_string(),
            alt_ips: Vec::new(),
            possible_alias_of: None,
            scan_metadata: Arc::new(ScanMetadata::default()),
        }
    }

    fn outcome_with_oid(oid: &str) -> ProbeOutcome {
        ProbeOutcome {
            lldp: None,
            gnmi_endpoint: None,
            kind: ProbeKind::Snmp,
            target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            timestamp: SystemTime::UNIX_EPOCH,
            reachable: true,
            signals: vec![Signal::SnmpSysObjectId(oid.to_string())],
            fault: None,
        }
    }

    #[test]
    fn oid_key_round_trips_prober_dotted_form() {
        let table = MibTable::from_bundled().expect("bundled loads");
        let dotted = arcs_to_dotted(&[1, 3, 6, 1, 4, 1, 6527, 1, 20, 26]);
        assert_eq!(dotted, SRLINUX_OID);
        let entry = table
            .lookup(&dotted)
            .expect("prober dotted form must hit the table");
        assert_eq!(entry.model.as_deref(), Some("SR Linux"));
    }

    #[test]
    fn parser_rejects_leading_dot_key_with_line_number() {
        let input = "1.3.6.1\tNokia\tSR Linux\tSR Linux\n.1.3.6.1.4.1.9\tCisco\tModel\tFamily\n";
        match parse_mib(Cursor::new(input)) {
            Ok(_) => panic!("expected parse error on leading-dot key"),
            Err(ParseError::Line { line, message }) => {
                assert_eq!(line, 2);
                assert!(message.contains("dotted-decimal"), "message was: {message}");
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn parser_rejects_whitespace_in_key() {
        let input = "1.3.6. 1\tNokia\tModel\tFamily\n";
        match parse_mib(Cursor::new(input)) {
            Ok(_) => panic!("expected parse error on whitespace key"),
            Err(ParseError::Line { line, .. }) => assert_eq!(line, 1),
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn parser_rejects_single_arc_key() {
        assert!(parse_mib(Cursor::new("6527\tNokia\tModel\tFamily\n")).is_err());
    }

    #[test]
    fn parser_rejects_line_with_five_columns() {
        let input = "1.3.6.1\tNokia\tSR Linux\tSR Linux\trole=switch\n";
        match parse_mib(Cursor::new(input)) {
            Ok(_) => panic!("expected parse error on 5-column line"),
            Err(ParseError::Line { line, message }) => {
                assert_eq!(line, 1);
                assert!(
                    message.contains("4 tab-separated"),
                    "message was: {message}"
                );
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn parser_rejects_line_with_three_columns() {
        assert!(parse_mib(Cursor::new("1.3.6.1\tNokia\tSR Linux\n")).is_err());
    }

    #[test]
    fn parser_allows_empty_model_column_with_product_family() {
        let table = parse_str("1.3.6.1.4.1.8072.3.2.10\t\t\tlinux\n");
        let entry = table.lookup("1.3.6.1.4.1.8072.3.2.10").expect("hit");
        assert!(entry.manufacturer.is_none());
        assert!(entry.model.is_none());
        assert_eq!(entry.product_family.as_deref(), Some("linux"));
    }

    #[test]
    fn parser_rejects_row_with_no_identity_columns() {
        assert!(parse_mib(Cursor::new("1.3.6.1\t\t\t\n")).is_err());
    }

    #[test]
    fn parser_allows_empty_manufacturer_column() {
        let table = parse_str("1.3.6.1\t\tSR Linux\tSR Linux\n");
        let entry = table.lookup("1.3.6.1").expect("hit");
        assert!(entry.manufacturer.is_none());
        assert_eq!(entry.model.as_deref(), Some("SR Linux"));
    }

    #[test]
    fn parser_preserves_internal_spaces_in_model() {
        let table = parse_str("1.3.6.1\tNokia\t7250 IXR-6e\tSR Linux\n");
        assert_eq!(
            table.lookup("1.3.6.1").expect("hit").model.as_deref(),
            Some("7250 IXR-6e")
        );
    }

    #[test]
    fn parser_skips_comments_and_blank_lines() {
        let table = parse_str("# header\n\n   \n1.3.6.1\tNokia\tSR Linux\tSR Linux\n");
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn lookup_is_exact_match_not_prefix() {
        let table = parse_str("1.3.6.1.4.1.9.1.2494\tCisco\tCatalyst\tswitch\n");
        assert!(table.lookup("1.3.6.1.4.1.9.1").is_none());
        assert!(table.lookup("1.3.6.1.4.1.9.1.2494.1").is_none());
        assert!(table.lookup("1.3.6.1.4.1.9.1.2494").is_some());
    }

    #[test]
    fn bundled_data_loads_and_contains_lab_verified_oid() {
        let table = MibTable::from_bundled().expect("bundled loads");
        let entry = table
            .lookup(SRLINUX_OID)
            .expect("SR Linux OID captured from the containerlab node");
        assert_eq!(entry.manufacturer.as_deref(), Some("Nokia"));
        assert_eq!(entry.model.as_deref(), Some("SR Linux"));
        assert!(table.lookup(NETSNMP_LINUX_OID).is_some());
    }

    #[test]
    fn bundled_net_snmp_row_carries_product_family_only() {
        let table = MibTable::from_bundled().expect("bundled loads");
        let entry = table.lookup(NETSNMP_LINUX_OID).expect("net-snmp linux OID");
        assert_eq!(entry.product_family.as_deref(), Some("linux"));
        assert!(
            entry.manufacturer.is_none(),
            "net-snmp is not a hardware vendor"
        );
        assert!(
            entry.model.is_none(),
            "net-snmp agent is not a hardware model"
        );
    }

    #[test]
    fn bundled_table_is_within_cap() {
        let table = MibTable::from_bundled().expect("bundled loads");
        assert!(
            table.len() <= MAX_BUNDLED_MIB_ENTRIES,
            "bundled MIB table has {} entries; cap is {MAX_BUNDLED_MIB_ENTRIES}",
            table.len()
        );
    }

    #[test]
    fn enrichment_writes_model_and_family_and_fills_absent_manufacturer() {
        let table = MibTable::from_bundled().expect("bundled loads");
        let fuser = MibEnrichmentFuser::new(Box::new(DirectFuser::new()), table);
        let mut record = record_with(Some(SRLINUX_OID), None);
        fuser.enrich(&mut record);
        assert_eq!(record.model.as_deref(), Some("SR Linux"));
        assert_eq!(record.product_family.as_deref(), Some("SR Linux"));
        assert_eq!(record.manufacturer.as_deref(), Some("Nokia"));
    }

    #[test]
    fn enrichment_preserves_existing_manufacturer_on_hit() {
        let table = MibTable::from_bundled().expect("bundled loads");
        let fuser = MibEnrichmentFuser::new(Box::new(DirectFuser::new()), table);
        let mut record = record_with(Some(SRLINUX_OID), Some("Acme Networks"));
        fuser.enrich(&mut record);
        assert_eq!(record.manufacturer.as_deref(), Some("Acme Networks"));
        assert_eq!(record.model.as_deref(), Some("SR Linux"));
    }

    #[test]
    fn enrichment_of_net_snmp_oid_sets_product_family_only() {
        let table = MibTable::from_bundled().expect("bundled loads");
        let fuser = MibEnrichmentFuser::new(Box::new(DirectFuser::new()), table);
        let mut record = record_with(Some(NETSNMP_LINUX_OID), None);
        fuser.enrich(&mut record);
        assert_eq!(record.product_family.as_deref(), Some("linux"));
        assert!(
            record.model.is_none(),
            "blanked model column stays unwritten"
        );
        assert!(
            record.manufacturer.is_none(),
            "blanked manufacturer column stays unwritten"
        );
    }

    #[test]
    fn enrichment_no_writes_when_no_sys_object_id_signal() {
        let table = MibTable::from_bundled().expect("bundled loads");
        let fuser = MibEnrichmentFuser::new(Box::new(DirectFuser::new()), table);
        let mut record = record_with(None, None);
        fuser.enrich(&mut record);
        assert!(record.model.is_none());
        assert!(record.product_family.is_none());
        assert!(record.manufacturer.is_none());
    }

    #[test]
    fn enrichment_no_writes_when_oid_misses_table() {
        let table = MibTable::from_bundled().expect("bundled loads");
        let fuser = MibEnrichmentFuser::new(Box::new(DirectFuser::new()), table);
        let mut record = record_with(Some("1.2.3.4.5.6.7.8.9"), None);
        fuser.enrich(&mut record);
        assert!(record.model.is_none());
        assert!(record.product_family.is_none());
        assert!(record.manufacturer.is_none());
    }

    #[test]
    fn ingest_enriches_a_hitting_record() {
        let table = MibTable::from_bundled().expect("bundled loads");
        let mut fuser = MibEnrichmentFuser::new(Box::new(DirectFuser::new()), table);
        let records = fuser
            .ingest(vec![outcome_with_oid(SRLINUX_OID)])
            .expect("ok");
        assert_eq!(records[0].model.as_deref(), Some("SR Linux"));
    }

    #[test]
    fn from_path_overlays_user_entries_on_bundled_seed() {
        use tempfile::NamedTempFile;
        let tmp = NamedTempFile::new().expect("tmp");
        std::fs::write(
            tmp.path(),
            "1.3.6.1.4.1.6527.1.20.26\tNokia\tSR Linux 7250 IXR\tSR Linux\n9.9.9.9\tAcme\tWidget\twidgets\n",
        )
        .expect("write");
        let path = tmp.path().to_str().expect("utf-8 path");
        let table = MibTable::from_path(path).expect("load");

        assert!(
            table.lookup(NETSNMP_LINUX_OID).is_some(),
            "bundled seed entry survives the overlay"
        );
        assert_eq!(
            table.lookup(SRLINUX_OID).expect("hit").model.as_deref(),
            Some("SR Linux 7250 IXR"),
            "overlay wins on a colliding key"
        );
        assert_eq!(
            table.lookup("9.9.9.9").expect("hit").model.as_deref(),
            Some("Widget"),
            "overlay adds a new key"
        );
    }

    #[test]
    fn from_path_returns_error_for_nonexistent_file() {
        match MibTable::from_path("/does/not/exist/mib.tsv") {
            Ok(_) => panic!("expected error for missing file"),
            Err(err) => {
                let msg = format!("{err}");
                assert!(msg.contains("/does/not/exist/mib.tsv"), "msg was: {msg}");
                assert!(msg.contains("could not be opened"), "msg was: {msg}");
            }
        }
    }

    #[test]
    fn from_path_returns_error_with_line_number_for_malformed_overlay() {
        use tempfile::NamedTempFile;
        let tmp = NamedTempFile::new().expect("tmp");
        std::fs::write(tmp.path(), "1.3.6.1\tNokia\tModel\tFamily\trole=x\n").expect("write");
        let path = tmp.path().to_str().expect("utf-8 path");
        match MibTable::from_path(path) {
            Ok(_) => panic!("expected error for malformed overlay"),
            Err(err) => {
                let msg = format!("{err}");
                assert!(msg.contains("line 1"), "msg was: {msg}");
                assert!(msg.contains(path), "msg was: {msg}");
            }
        }
    }

    #[test]
    fn mib_table_and_fuser_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MibTable>();
        assert_send_sync::<MibEnrichmentFuser>();
    }
}
