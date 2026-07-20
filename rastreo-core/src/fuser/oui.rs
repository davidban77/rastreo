use std::collections::HashMap;
use std::io::BufRead;

use crate::error::{ConfigError, RastreoError};
use crate::fuser::Fuser;
use crate::model::device::DeviceRecord;
use crate::model::outcome::ProbeOutcome;

const BUNDLED_MANUF_GZ: &[u8] = include_bytes!("../../data/manuf.gz");

pub fn default_data_path() -> String {
    String::new()
}

pub struct OuiEnrichmentFuser {
    inner: Box<dyn Fuser>,
    table: OuiTable,
}

impl OuiEnrichmentFuser {
    pub fn new(inner: Box<dyn Fuser>, table: OuiTable) -> Self {
        Self { inner, table }
    }

    fn enrich(&self, record: &mut DeviceRecord) {
        if record.manufacturer.is_none() {
            if let Some(mac) = &record.mac {
                if let Some(vendor) = self.table.lookup(mac) {
                    record.manufacturer = Some(vendor.to_string());
                }
            }
        }
    }
}

impl Fuser for OuiEnrichmentFuser {
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

pub struct OuiTable {
    entries_24: Vec<(u64, u32)>,
    entries_28: Vec<(u64, u32)>,
    entries_36: Vec<(u64, u32)>,
    vendors: Vec<String>,
}

const MASK_24: u64 = 0xFFFF_FF00_0000_0000;
const MASK_28: u64 = 0xFFFF_FFF0_0000_0000;
const MASK_36: u64 = 0xFFFF_FFFF_F000_0000;

#[derive(Clone, Copy)]
enum PrefixKind {
    L,
    M,
    S,
}

impl PrefixKind {
    fn mask(self) -> u64 {
        match self {
            Self::L => MASK_24,
            Self::M => MASK_28,
            Self::S => MASK_36,
        }
    }

    fn byte_len(self) -> usize {
        match self {
            Self::L => 3,
            Self::M => 4,
            Self::S => 5,
        }
    }
}

impl OuiTable {
    pub fn from_bundled() -> Result<Self, RastreoError> {
        use flate2::read::GzDecoder;
        let decoder = GzDecoder::new(BUNDLED_MANUF_GZ);
        let reader = std::io::BufReader::new(decoder);
        parse_manuf(reader).map_err(|e| match e {
            ParseError::Line { line, message } => RastreoError::Config(ConfigError::invalid(
                format!("failed to parse bundled OUI database: line {line}: {message}"),
            )),
            ParseError::Io(msg) => RastreoError::Config(ConfigError::invalid(format!(
                "failed to read bundled OUI database: {msg}"
            ))),
        })
    }

    pub fn from_path(path: &str) -> Result<Self, RastreoError> {
        let file = std::fs::File::open(path).map_err(|e| {
            RastreoError::Config(ConfigError::invalid(format!(
                "OUI data file '{path}' could not be opened: {e}"
            )))
        })?;
        let reader = std::io::BufReader::new(file);
        parse_manuf(reader).map_err(|e| match e {
            ParseError::Line { line, message } => {
                RastreoError::Config(ConfigError::invalid(format!(
                    "OUI data file '{path}' is not a valid manuf-format file: line {line}: {message}"
                )))
            }
            ParseError::Io(msg) => RastreoError::Config(ConfigError::invalid(format!(
                "OUI data file '{path}' could not be read: {msg}"
            ))),
        })
    }

    pub fn lookup(&self, mac: &str) -> Option<&str> {
        let packed = parse_mac_to_u64(mac)?;
        if let Some(idx) = search_prefix(&self.entries_36, packed & MASK_36) {
            return Some(self.vendors[idx as usize].as_str());
        }
        if let Some(idx) = search_prefix(&self.entries_28, packed & MASK_28) {
            return Some(self.vendors[idx as usize].as_str());
        }
        if let Some(idx) = search_prefix(&self.entries_24, packed & MASK_24) {
            return Some(self.vendors[idx as usize].as_str());
        }
        None
    }

    pub fn entry_count(&self) -> usize {
        self.entries_24.len() + self.entries_28.len() + self.entries_36.len()
    }

    pub fn vendor_count(&self) -> usize {
        self.vendors.len()
    }
}

fn search_prefix(sorted: &[(u64, u32)], key: u64) -> Option<u32> {
    sorted
        .binary_search_by_key(&key, |&(k, _)| k)
        .ok()
        .map(|i| sorted[i].1)
}

#[derive(Debug)]
enum ParseError {
    Line { line: usize, message: String },
    Io(String),
}

fn parse_manuf<R: BufRead>(reader: R) -> Result<OuiTable, ParseError> {
    let mut entries_24: Vec<(u64, u32)> = Vec::new();
    let mut entries_28: Vec<(u64, u32)> = Vec::new();
    let mut entries_36: Vec<(u64, u32)> = Vec::new();
    let mut vendors: Vec<String> = Vec::new();
    let mut seen: HashMap<String, u32> = HashMap::new();

    for (line_no_zero, raw) in reader.lines().enumerate() {
        let line_no = line_no_zero + 1;
        let raw = raw.map_err(|e| ParseError::Io(e.to_string()))?;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut cols = trimmed.split('\t').map(str::trim).filter(|s| !s.is_empty());
        let prefix_raw = cols.next().ok_or_else(|| ParseError::Line {
            line: line_no,
            message: "missing prefix column".into(),
        })?;
        let short_name = cols.next().unwrap_or("");
        let long_name = cols.next().unwrap_or("");

        let (packed, kind) =
            parse_prefix_column(prefix_raw).map_err(|message| ParseError::Line {
                line: line_no,
                message,
            })?;

        let vendor_name = if !long_name.is_empty() {
            long_name
        } else if !short_name.is_empty() {
            short_name
        } else {
            continue;
        };

        let idx = intern_vendor(&mut vendors, &mut seen, vendor_name);
        match kind {
            PrefixKind::L => entries_24.push((packed, idx)),
            PrefixKind::M => entries_28.push((packed, idx)),
            PrefixKind::S => entries_36.push((packed, idx)),
        }
    }

    entries_24.sort_by_key(|&(k, _)| k);
    entries_28.sort_by_key(|&(k, _)| k);
    entries_36.sort_by_key(|&(k, _)| k);

    Ok(OuiTable {
        entries_24,
        entries_28,
        entries_36,
        vendors,
    })
}

fn intern_vendor(vendors: &mut Vec<String>, seen: &mut HashMap<String, u32>, name: &str) -> u32 {
    if let Some(&idx) = seen.get(name) {
        return idx;
    }
    let idx = vendors.len() as u32;
    let owned = name.to_string();
    vendors.push(owned.clone());
    seen.insert(owned, idx);
    idx
}

fn parse_prefix_column(raw: &str) -> Result<(u64, PrefixKind), String> {
    let (mac_part, kind) = match raw.split_once('/') {
        Some((mac, mask)) => {
            let bits: u32 = mask
                .parse()
                .map_err(|_| format!("invalid prefix mask '{mask}'"))?;
            let kind = match bits {
                28 => PrefixKind::M,
                36 => PrefixKind::S,
                _ => {
                    return Err(format!(
                        "unsupported prefix mask '/{bits}' (expected /28 or /36)"
                    ))
                }
            };
            (mac, kind)
        }
        None => (raw, PrefixKind::L),
    };

    let bytes = parse_mac_bytes(mac_part)?;
    let expected = kind.byte_len();
    if bytes.len() != expected {
        return Err(format!(
            "prefix '{mac_part}' has {} bytes but /{} needs {expected}",
            bytes.len(),
            match kind {
                PrefixKind::L => 24,
                PrefixKind::M => 28,
                PrefixKind::S => 36,
            }
        ));
    }

    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(&bytes);
    let packed = u64::from_be_bytes(buf) & kind.mask();
    Ok((packed, kind))
}

fn parse_mac_bytes(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| *c != ':' && *c != '-').collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err(format!("MAC prefix '{s}' has odd hex-digit count"));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi =
            hex_nibble(chunk[0]).ok_or_else(|| format!("MAC prefix '{s}' has non-hex byte"))?;
        let lo =
            hex_nibble(chunk[1]).ok_or_else(|| format!("MAC prefix '{s}' has non-hex byte"))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn parse_mac_to_u64(mac: &str) -> Option<u64> {
    let mut acc: u64 = 0;
    let mut nibble_count: u32 = 0;
    for byte in mac.bytes() {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => 10 + (byte - b'a'),
            b'A'..=b'F' => 10 + (byte - b'A'),
            b':' | b'-' => continue,
            _ => return None,
        };
        if nibble_count == 12 {
            return None;
        }
        acc = (acc << 4) | (nibble as u64);
        nibble_count += 1;
    }
    if nibble_count != 12 {
        return None;
    }
    Some(acc << 16)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    use crate::fuser::DirectFuser;
    use crate::model::outcome::{ProbeKind, Signal};

    fn parse_str(input: &str) -> OuiTable {
        parse_manuf(Cursor::new(input)).expect("parse ok")
    }

    #[test]
    fn manuf_parser_ignores_comment_and_empty_lines() {
        let table =
            parse_str("# comment\n\n   \n00:00:0C\tCisco\tCisco Systems, Inc\n# tail comment\n");
        assert_eq!(table.entry_count(), 1);
        assert_eq!(
            table.lookup("00:00:0C:01:02:03"),
            Some("Cisco Systems, Inc")
        );
    }

    #[test]
    fn manuf_parser_extracts_24_bit_entry() {
        let table = parse_str("00:04:AC\tIBM\tIBM Corp\n");
        assert_eq!(table.lookup("00:04:AC:11:22:33"), Some("IBM Corp"));
    }

    #[test]
    fn manuf_parser_extracts_28_bit_entry_with_mask() {
        let table = parse_str("00:55:DA:00/28\tKoolPOS\tKoolPOS Inc.\n");
        assert_eq!(table.lookup("00:55:DA:0F:22:33"), Some("KoolPOS Inc."));
        assert_eq!(table.lookup("00:55:DA:10:00:00"), None);
    }

    #[test]
    fn manuf_parser_extracts_36_bit_entry_with_mask() {
        let table = parse_str("00:1B:C5:00:00/36\tConverging\tConverging Systems Inc.\n");
        assert_eq!(
            table.lookup("00:1B:C5:00:0F:99"),
            Some("Converging Systems Inc.")
        );
        assert_eq!(table.lookup("00:1B:C5:00:10:00"), None);
    }

    #[test]
    fn manuf_parser_prefers_long_name_over_short() {
        let table = parse_str("00:00:0C\tCisco\tCisco Systems, Inc\n");
        assert_eq!(
            table.lookup("00:00:0C:AA:BB:CC"),
            Some("Cisco Systems, Inc")
        );
    }

    #[test]
    fn manuf_parser_falls_back_to_short_name_when_long_is_missing() {
        let table = parse_str("00:00:0C\tCisco\n");
        assert_eq!(table.lookup("00:00:0C:AA:BB:CC"), Some("Cisco"));
    }

    #[test]
    fn manuf_parser_handles_tab_and_space_separated_columns() {
        let table = parse_str("00:00:0C   \tCisco       \tCisco Systems, Inc\n");
        assert_eq!(
            table.lookup("00:00:0C:AA:BB:CC"),
            Some("Cisco Systems, Inc")
        );
    }

    #[test]
    fn manuf_parser_rejects_malformed_line_returning_error_with_line_number() {
        let input = "00:00:0C\tCisco\tCisco Systems, Inc\nZZ:ZZ:ZZ\tBogus\tBogus\n";
        match parse_manuf(Cursor::new(input)) {
            Ok(_) => panic!("expected parse error on bad hex"),
            Err(ParseError::Line { line, message }) => {
                assert_eq!(line, 2);
                assert!(message.contains("ZZ:ZZ:ZZ"), "message was: {message}");
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn lookup_finds_24_bit_ma_l_match() {
        let table = parse_str("00:04:AC\tIBM\tIBM Corp\n");
        assert_eq!(table.lookup("00:04:AC:12:34:56"), Some("IBM Corp"));
    }

    #[test]
    fn lookup_prefers_36_bit_ma_s_over_24_bit_ma_l_on_same_prefix() {
        let input = "00:1B:C5\tGenericCorp\tGeneric MA-L Corp\n\
                     00:1B:C5:00:00/36\tSpecific\tSpecific MA-S Corp\n";
        let table = parse_str(input);
        assert_eq!(
            table.lookup("00:1B:C5:00:0F:AA"),
            Some("Specific MA-S Corp")
        );
        assert_eq!(table.lookup("00:1B:C5:AA:BB:CC"), Some("Generic MA-L Corp"));
    }

    #[test]
    fn lookup_prefers_28_bit_ma_m_when_no_ma_s_matches() {
        let input = "00:55:DA\tGenericCorp\tGeneric MA-L Corp\n\
                     00:55:DA:00/28\tMidTier\tMid-Tier MA-M Corp\n";
        let table = parse_str(input);
        assert_eq!(
            table.lookup("00:55:DA:0F:11:22"),
            Some("Mid-Tier MA-M Corp")
        );
        assert_eq!(table.lookup("00:55:DA:AA:BB:CC"), Some("Generic MA-L Corp"));
    }

    #[test]
    fn lookup_accepts_colon_separator_mac() {
        let table = parse_str("00:04:AC\tIBM\tIBM Corp\n");
        assert_eq!(table.lookup("00:04:AC:11:22:33"), Some("IBM Corp"));
    }

    #[test]
    fn lookup_accepts_hyphen_separator_mac() {
        let table = parse_str("00:04:AC\tIBM\tIBM Corp\n");
        assert_eq!(table.lookup("00-04-AC-11-22-33"), Some("IBM Corp"));
    }

    #[test]
    fn lookup_accepts_no_separator_mac() {
        let table = parse_str("00:04:AC\tIBM\tIBM Corp\n");
        assert_eq!(table.lookup("0004AC112233"), Some("IBM Corp"));
    }

    #[test]
    fn lookup_case_insensitive() {
        let table = parse_str("00:04:AC\tIBM\tIBM Corp\n");
        assert_eq!(table.lookup("00:04:ac:11:22:33"), Some("IBM Corp"));
        assert_eq!(table.lookup("00:04:aC:11:22:33"), Some("IBM Corp"));
    }

    #[test]
    fn lookup_returns_none_for_unknown_oui() {
        let table = parse_str("00:04:AC\tIBM\tIBM Corp\n");
        assert_eq!(table.lookup("FE:DC:BA:11:22:33"), None);
    }

    #[test]
    fn lookup_returns_none_for_malformed_mac_input() {
        let table = parse_str("00:04:AC\tIBM\tIBM Corp\n");
        assert_eq!(table.lookup("not-a-mac"), None);
        assert_eq!(table.lookup("00:04"), None);
        assert_eq!(table.lookup(""), None);
        assert_eq!(table.lookup("ZZ:04:AC:11:22:33"), None);
    }

    #[test]
    fn lookup_returns_none_for_too_many_hex_digits() {
        let table = parse_str("00:04:AC\tIBM\tIBM Corp\n");
        assert_eq!(table.lookup("00:04:AC:11:22:33:44"), None);
        assert_eq!(table.lookup("0004AC1122334455"), None);
    }

    #[test]
    fn bundled_data_loads_and_contains_known_ouis() {
        let table = OuiTable::from_bundled().expect("bundled loads");
        assert_eq!(
            table.lookup("08:00:20:00:00:00"),
            Some("Oracle Corporation"),
            "08:00:20 has been an Oracle allocation for decades"
        );
        assert_eq!(
            table.lookup("00:50:56:00:00:00"),
            Some("VMware, Inc."),
            "00:50:56 has been VMware for decades"
        );
        assert_eq!(
            table.lookup("00:00:0C:AA:BB:CC"),
            Some("Cisco Systems, Inc"),
            "00:00:0C is the canonical Cisco OUI"
        );
        assert_eq!(
            table.lookup("00:04:AC:AA:BB:CC"),
            Some("IBM Corp"),
            "00:04:AC is the canonical IBM OUI"
        );
    }

    #[test]
    fn bundled_manuf_gz_is_not_stale() {
        let table = OuiTable::from_bundled().expect("bundled loads");
        assert!(
            table.entry_count() > 40_000,
            "bundled manuf.gz has {} entries; expected > 40000 (IEEE has assigned >50k OUIs; a lower count suggests a truncated refresh — re-run scripts/refresh-oui.sh)",
            table.entry_count()
        );
    }

    #[test]
    fn bundled_data_dedups_vendor_strings() {
        let table = OuiTable::from_bundled().expect("bundled loads");
        assert!(
            table.vendor_count() < table.entry_count(),
            "vendors ({}) should be fewer than entries ({}) — dedup should collapse repeated names",
            table.vendor_count(),
            table.entry_count()
        );
        let saved = table.entry_count() - table.vendor_count();
        assert!(
            saved > table.entry_count() / 5,
            "dedup should save at least 20% of entries; saved {} of {} entries",
            saved,
            table.entry_count()
        );
    }

    #[test]
    fn small_input_dedups_repeated_vendor_across_prefixes() {
        let input = "00:00:0C\tCisco\tCisco Systems, Inc\n\
                     00:00:0D\tCisco\tCisco Systems, Inc\n\
                     00:00:0E\tCisco\tCisco Systems, Inc\n";
        let table = parse_str(input);
        assert_eq!(table.entry_count(), 3);
        assert_eq!(table.vendor_count(), 1);
    }

    fn outcome_with_mac(mac: &str) -> ProbeOutcome {
        ProbeOutcome {
            lldp: None,
            gnmi_endpoint: None,
            kind: ProbeKind::TcpConnect,
            target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            timestamp: SystemTime::UNIX_EPOCH,
            reachable: true,
            signals: vec![Signal::Mac(mac.to_string()), Signal::OpenPort(22)],
            fault: None,
        }
    }

    fn outcome_no_mac() -> ProbeOutcome {
        ProbeOutcome {
            lldp: None,
            gnmi_endpoint: None,
            kind: ProbeKind::TcpConnect,
            target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            timestamp: SystemTime::UNIX_EPOCH,
            reachable: true,
            signals: vec![Signal::OpenPort(80)],
            fault: None,
        }
    }

    #[test]
    fn oui_enrichment_populates_manufacturer_from_bundled_data() {
        let table = OuiTable::from_bundled().expect("bundled loads");
        let mut fuser = OuiEnrichmentFuser::new(Box::new(DirectFuser::new()), table);
        let outcomes = vec![outcome_with_mac("00:04:AC:11:22:33")];
        let records = fuser.ingest(outcomes).expect("ok");
        assert_eq!(records[0].manufacturer.as_deref(), Some("IBM Corp"));
    }

    #[test]
    fn oui_enrichment_leaves_manufacturer_none_when_no_mac_in_record() {
        let table = OuiTable::from_bundled().expect("bundled loads");
        let mut fuser = OuiEnrichmentFuser::new(Box::new(DirectFuser::new()), table);
        let outcomes = vec![outcome_no_mac()];
        let records = fuser.ingest(outcomes).expect("ok");
        assert!(records[0].mac.is_none());
        assert!(records[0].manufacturer.is_none());
    }

    #[test]
    fn oui_enrichment_leaves_manufacturer_none_when_oui_unknown() {
        let table = parse_str("00:04:AC\tIBM\tIBM Corp\n");
        let mut fuser = OuiEnrichmentFuser::new(Box::new(DirectFuser::new()), table);
        let outcomes = vec![outcome_with_mac("FE:DC:BA:11:22:33")];
        let records = fuser.ingest(outcomes).expect("ok");
        assert!(records[0].manufacturer.is_none());
    }

    #[test]
    fn oui_enrichment_delegates_to_inner_fuser() {
        let table = OuiTable::from_bundled().expect("bundled loads");
        let mut fuser = OuiEnrichmentFuser::new(
            Box::new(DirectFuser::new().with_confidence_baseline(0.5)),
            table,
        );
        let outcomes = vec![outcome_with_mac("00:04:AC:11:22:33")];
        let records = fuser.ingest(outcomes).expect("ok");
        // Baseline 0.5 + 2 signals * 0.1 = 0.7
        assert!((records[0].confidence.value() - 0.7).abs() < 1e-9);
    }

    #[test]
    fn oui_enrichment_returns_empty_when_inner_returns_empty() {
        let table = OuiTable::from_bundled().expect("bundled loads");
        let mut fuser = OuiEnrichmentFuser::new(Box::new(DirectFuser::new()), table);
        let records = fuser.ingest(Vec::new()).expect("ok");
        assert!(records.is_empty());
    }

    #[test]
    fn oui_table_from_path_returns_error_for_nonexistent_file() {
        match OuiTable::from_path("/does/not/exist/manuf.txt") {
            Ok(_) => panic!("expected error for missing file"),
            Err(err) => {
                let msg = format!("{err}");
                assert!(msg.contains("/does/not/exist/manuf.txt"), "msg was: {msg}");
                assert!(msg.contains("could not be opened"), "msg was: {msg}");
            }
        }
    }

    #[test]
    fn oui_table_from_path_returns_error_with_line_number_for_malformed_file() {
        use tempfile::NamedTempFile;
        let tmp = NamedTempFile::new().expect("tmp");
        std::fs::write(
            tmp.path(),
            "00:04:AC\tIBM\tIBM Corp\nZZ:ZZ:ZZ\tBogus\tBogus\n",
        )
        .expect("write");
        let path = tmp.path().to_str().expect("utf-8 path");
        match OuiTable::from_path(path) {
            Ok(_) => panic!("expected error for malformed file"),
            Err(err) => {
                let msg = format!("{err}");
                assert!(msg.contains("line 2"), "msg was: {msg}");
                assert!(msg.contains(path), "msg was: {msg}");
            }
        }
    }

    #[test]
    fn default_data_path_is_empty_string() {
        assert_eq!(default_data_path(), "");
    }

    #[test]
    fn oui_table_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OuiTable>();
        assert_send_sync::<OuiEnrichmentFuser>();
    }
}
