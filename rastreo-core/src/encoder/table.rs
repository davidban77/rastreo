//! Fixed-width table output for reading a scan at a glance.
//!
//! The table is a triage view; the complete record is what the NDJSON encoder emits. Columns share
//! one line width, so adding one narrows the rest.

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::RastreoError;
use crate::model::{CollectionProfileRecord, DeviceRecord, LinkRecord, Signal};

use super::Encoder;

struct Column {
    header: &'static str,
    min: u16,
    max: u16,
}

const COLUMNS: [Column; 4] = [
    Column {
        header: "ADDRESS",
        min: 15,
        max: 39,
    },
    Column {
        header: "NAME",
        min: 12,
        max: 40,
    },
    Column {
        header: "PLATFORM",
        min: 10,
        max: 20,
    },
    Column {
        header: "PORTS",
        min: 12,
        max: 48,
    },
];

const SEPARATOR: &[u8] = b"  ";
const ELLIPSIS: &[u8] = "…".as_bytes();
const SPACES: &[u8; 64] = &[b' '; 64];

const fn gutter_width() -> u16 {
    (SEPARATOR.len() * (COLUMNS.len() - 1)) as u16
}

const fn min_total_width() -> u16 {
    let mut sum = gutter_width();
    let mut i = 0;
    while i < COLUMNS.len() {
        sum += COLUMNS[i].min;
        i += 1;
    }
    sum
}

#[cfg(test)]
const fn max_total_width() -> u16 {
    let mut sum = gutter_width();
    let mut i = 0;
    while i < COLUMNS.len() {
        sum += COLUMNS[i].max;
        i += 1;
    }
    sum
}

/// Narrowest total width the table renders at; a smaller request is clamped up to it.
pub(crate) const MIN_TOTAL_WIDTH: u16 = min_total_width();

/// Widest total width the table renders at; a larger request saturates at it.
#[cfg(test)]
pub(crate) const MAX_TOTAL_WIDTH: u16 = max_total_width();

/// Serde default for `EncoderConfig::Table.width` — `100`.
pub fn default_width() -> u16 {
    100
}

/// Column widths resolved from one total line width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TableLayout {
    widths: [u16; COLUMNS.len()],
}

impl TableLayout {
    /// Seeds every column at its minimum, then hands the surplus out one character at a time,
    /// round-robin, skipping any column already at its maximum.
    pub(crate) fn for_total_width(total: u16) -> Self {
        let mut widths = [0u16; COLUMNS.len()];
        for (width, column) in widths.iter_mut().zip(COLUMNS.iter()) {
            *width = column.min;
        }
        let mut surplus = total.saturating_sub(MIN_TOTAL_WIDTH);
        while surplus > 0 {
            let mut grew = false;
            for (width, column) in widths.iter_mut().zip(COLUMNS.iter()) {
                if surplus == 0 {
                    break;
                }
                if *width < column.max {
                    *width += 1;
                    surplus -= 1;
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        Self { widths }
    }

    #[cfg(test)]
    pub(crate) fn widths(&self) -> &[u16] {
        &self.widths
    }

    #[cfg(test)]
    pub(crate) fn total_width(&self) -> u16 {
        self.widths.iter().sum::<u16>() + gutter_width()
    }
}

/// Renders device records as aligned rows. The header is written before the first record and never
/// again, so one encoder renders one table — reusing it across scans emits no second header.
pub struct TableEncoder {
    layout: TableLayout,
    header: String,
    header_written: AtomicBool,
}

impl TableEncoder {
    pub fn new(total_width: u16) -> Self {
        let layout = TableLayout::for_total_width(total_width);
        let header = build_header(&layout);
        Self {
            layout,
            header,
            header_written: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    pub(crate) fn layout(&self) -> &TableLayout {
        &self.layout
    }
}

impl Default for TableEncoder {
    fn default() -> Self {
        Self::new(default_width())
    }
}

impl Encoder for TableEncoder {
    fn encode_record(&self, record: &DeviceRecord, buf: &mut Vec<u8>) -> Result<(), RastreoError> {
        if !self.header_written.swap(true, Ordering::Relaxed) {
            buf.extend_from_slice(self.header.as_bytes());
        }
        let widths = &self.layout.widths;

        let start = buf.len();
        match &record.mgmt_ip {
            // io::Write on a Vec<u8> cannot fail.
            Some(ip) => {
                let _ = write!(buf, "{ip}");
            }
            None => buf.extend_from_slice(record.identity_key.as_str().as_bytes()),
        }
        finish_cell(buf, start, widths[0], false);

        let start = buf.len();
        if let Some(name) = device_name(record) {
            buf.extend_from_slice(name.as_bytes());
        }
        finish_cell(buf, start, widths[1], false);

        let start = buf.len();
        if let Some(platform) = platform_label(record) {
            buf.extend_from_slice(platform.as_bytes());
        }
        finish_cell(buf, start, widths[2], false);

        let start = buf.len();
        write_open_ports(record, buf);
        finish_cell(buf, start, widths[3], true);

        buf.push(b'\n');
        Ok(())
    }

    fn encode_link(&self, _link: &LinkRecord, _buf: &mut Vec<u8>) -> Result<(), RastreoError> {
        Ok(())
    }

    fn encode_profile(
        &self,
        _profile: &CollectionProfileRecord,
        _buf: &mut Vec<u8>,
    ) -> Result<(), RastreoError> {
        Ok(())
    }
}

/// The device's own name: its SNMP `sysName`, else the PTR record it resolved to.
fn device_name(record: &DeviceRecord) -> Option<&str> {
    let sys_name = record.signals.iter().find_map(|s| match s {
        Signal::SnmpSysName(name) => Some(name.as_str()),
        _ => None,
    });
    sys_name.or_else(|| {
        record.signals.iter().find_map(|s| match s {
            Signal::ReverseDnsName(name) => Some(name.as_str()),
            _ => None,
        })
    })
}

fn platform_label(record: &DeviceRecord) -> Option<&str> {
    record
        .platform
        .as_deref()
        .or(record.model.as_deref())
        .or(record.product_family.as_deref())
}

fn write_open_ports(record: &DeviceRecord, buf: &mut Vec<u8>) {
    let mut first = true;
    for signal in &record.signals {
        if let Signal::OpenPort(port) = signal {
            if !first {
                buf.push(b',');
            }
            push_u16(buf, *port);
            first = false;
        }
    }
}

fn push_u16(buf: &mut Vec<u8>, mut value: u16) {
    let mut digits = [0u8; 5];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    buf.extend_from_slice(&digits[i..]);
}

fn build_header(layout: &TableLayout) -> String {
    let mut buf = Vec::new();
    let last = COLUMNS.len() - 1;
    for (i, (column, width)) in COLUMNS.iter().zip(layout.widths).enumerate() {
        let start = buf.len();
        buf.extend_from_slice(column.header.as_bytes());
        finish_cell(&mut buf, start, width, i == last);
    }
    buf.push(b'\n');
    String::from_utf8_lossy(&buf).into_owned()
}

/// Dashes an empty cell, then pads or truncates it to `width` and appends the separator. The row's
/// last cell is only dashed: it is neither padded nor truncated.
fn finish_cell(buf: &mut Vec<u8>, start: usize, width: u16, last: bool) {
    if buf.len() == start {
        buf.push(b'-');
    }
    // A last cell has no successor to stay aligned with, so it runs over rather than losing data.
    if last {
        return;
    }
    let width = usize::from(width);
    let mut chars = char_count(&buf[start..]);
    if chars > width {
        let keep = width.saturating_sub(1);
        let cut = start + byte_index_of_char(&buf[start..], keep);
        buf.truncate(cut);
        buf.extend_from_slice(ELLIPSIS);
        chars = keep + 1;
    }
    push_spaces(buf, width.saturating_sub(chars));
    buf.extend_from_slice(SEPARATOR);
}

fn push_spaces(buf: &mut Vec<u8>, mut count: usize) {
    while count > 0 {
        let chunk = count.min(SPACES.len());
        buf.extend_from_slice(&SPACES[..chunk]);
        count -= chunk;
    }
}

fn char_count(bytes: &[u8]) -> usize {
    bytes.iter().filter(|b| (**b & 0xC0) != 0x80).count()
}

fn byte_index_of_char(bytes: &[u8], n: usize) -> usize {
    let mut seen = 0;
    for (i, b) in bytes.iter().enumerate() {
        if (*b & 0xC0) != 0x80 {
            if seen == n {
                return i;
            }
            seen += 1;
        }
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::time::SystemTime;

    use rstest::rstest;

    use crate::model::{
        Confidence, IdentityKey, ScanMetadata, CURRENT_SCHEMA_ID, CURRENT_SCHEMA_VERSION,
    };

    const NAME: usize = 1;
    const PLATFORM: usize = 2;
    const PORTS: usize = 3;

    fn record() -> DeviceRecord {
        DeviceRecord {
            identity_key: IdentityKey::new("ip:10.0.0.1").expect("identity"),
            mgmt_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            mac: None,
            manufacturer: None,
            model: None,
            product_family: None,
            platform: None,
            os_version: None,
            ssh_version: None,
            http_server: None,
            http_version: None,
            role: None,
            confidence: Confidence::new(0.5).expect("confidence"),
            last_seen: SystemTime::UNIX_EPOCH,
            signals: Vec::new(),
            probe_kinds: Vec::new(),
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
            schema_id: CURRENT_SCHEMA_ID.to_string(),
            alt_ips: Vec::new(),
            possible_alias_of: None,
            scan_metadata: Arc::new(ScanMetadata::default()),
        }
    }

    fn named(name: &str) -> DeviceRecord {
        let mut r = record();
        r.signals = vec![Signal::SnmpSysName(name.into())];
        r
    }

    fn encode(encoder: &TableEncoder, records: &[DeviceRecord]) -> String {
        let mut out = String::new();
        for record in records {
            let mut buf = Vec::new();
            encoder.encode_record(record, &mut buf).expect("encode");
            out.push_str(&String::from_utf8_lossy(&buf));
        }
        out
    }

    fn rows(rendered: &str) -> Vec<&str> {
        rendered.lines().skip(1).collect()
    }

    fn cells(row: &str) -> Vec<String> {
        row.split("  ")
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn header_names_the_four_columns_in_order() {
        let rendered = encode(&TableEncoder::default(), &[record()]);
        let header = rendered.lines().next().expect("header line");
        assert_eq!(cells(header), vec!["ADDRESS", "NAME", "PLATFORM", "PORTS"]);
    }

    #[test]
    fn the_manufacturer_is_not_a_column() {
        let mut r = record();
        r.manufacturer = Some("Cisco Systems".into());
        let rendered = encode(&TableEncoder::default(), &[r]);
        assert!(!rendered.contains("Cisco"), "rendered:\n{rendered}");
    }

    #[test]
    fn header_is_emitted_once_across_many_records() {
        let rendered = encode(&TableEncoder::default(), &[record(), record(), record()]);
        assert_eq!(
            rendered.matches("ADDRESS").count(),
            1,
            "header must appear exactly once:\n{rendered}"
        );
        assert_eq!(rendered.lines().count(), 4);
    }

    #[test]
    fn header_is_not_re_emitted_after_the_caller_clears_the_buffer() {
        let encoder = TableEncoder::default();
        let mut buf = Vec::new();
        encoder.encode_record(&record(), &mut buf).expect("first");
        buf.clear();
        encoder.encode_record(&record(), &mut buf).expect("second");
        let second = String::from_utf8_lossy(&buf);
        assert!(!second.contains("ADDRESS"), "second write was: {second}");
    }

    #[test]
    fn every_absent_field_renders_as_a_single_dash() {
        let rendered = encode(&TableEncoder::default(), &[record()]);
        let row = rows(&rendered)[0];
        assert_eq!(cells(row), vec!["10.0.0.1", "-", "-", "-"]);
    }

    #[test]
    fn address_falls_back_to_the_identity_key_when_no_mgmt_ip_is_known() {
        let mut r = record();
        r.mgmt_ip = None;
        r.identity_key = IdentityKey::new("mac:aa:bb:cc:dd:ee:ff").expect("identity");
        let rendered = encode(&TableEncoder::default(), &[r]);
        assert_eq!(cells(rows(&rendered)[0])[0], "mac:aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn ipv6_addresses_render_in_full() {
        let mut r = record();
        r.mgmt_ip = Some(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1234,
        )));
        let rendered = encode(&TableEncoder::default(), &[r]);
        assert_eq!(cells(rows(&rendered)[0])[0], "2001:db8::1234");
    }

    #[test]
    fn name_uses_the_snmp_sys_name() {
        let rendered = encode(&TableEncoder::default(), &[named("access-sw-01")]);
        assert_eq!(cells(rows(&rendered)[0])[NAME], "access-sw-01");
    }

    #[test]
    fn name_falls_back_to_the_reverse_dns_record() {
        let mut r = record();
        r.signals = vec![Signal::ReverseDnsName("one.one.one.one".into())];
        let rendered = encode(&TableEncoder::default(), &[r]);
        assert_eq!(cells(rows(&rendered)[0])[NAME], "one.one.one.one");
    }

    #[test]
    fn name_prefers_the_snmp_sys_name_over_the_reverse_dns_record() {
        let mut r = record();
        r.signals = vec![
            Signal::ReverseDnsName("ptr.example.com".into()),
            Signal::SnmpSysName("srl-01".into()),
        ];
        let rendered = encode(&TableEncoder::default(), &[r]);
        assert_eq!(cells(rows(&rendered)[0])[NAME], "srl-01");
    }

    #[rstest]
    #[case(Some("cisco_ios"), Some("C2960"), Some("catalyst"), "cisco_ios")]
    #[case(None, Some("C2960"), Some("catalyst"), "C2960")]
    #[case(None, None, Some("catalyst"), "catalyst")]
    #[case(None, None, None, "-")]
    fn platform_falls_back_through_model_then_product_family(
        #[case] platform: Option<&str>,
        #[case] model: Option<&str>,
        #[case] product_family: Option<&str>,
        #[case] expected: &str,
    ) {
        let mut r = record();
        r.platform = platform.map(str::to_string);
        r.model = model.map(str::to_string);
        r.product_family = product_family.map(str::to_string);
        let rendered = encode(&TableEncoder::default(), &[r]);
        assert_eq!(cells(rows(&rendered)[0])[PLATFORM], expected);
    }

    #[test]
    fn ports_are_comma_joined_from_the_open_port_signals_in_record_order() {
        let mut r = record();
        r.signals = vec![
            Signal::OpenPort(22),
            Signal::SshBanner("SSH-2.0-OpenSSH_9.6".into()),
            Signal::OpenPort(443),
            Signal::OpenPort(8080),
        ];
        let rendered = encode(&TableEncoder::default(), &[r]);
        assert_eq!(cells(rows(&rendered)[0])[PORTS], "22,443,8080");
    }

    #[test]
    fn a_record_with_no_open_port_signal_dashes_the_ports_cell() {
        let rendered = encode(&TableEncoder::default(), &[named("darwin-box")]);
        assert_eq!(cells(rows(&rendered)[0])[PORTS], "-");
    }

    #[test]
    fn the_default_probe_set_of_open_ports_survives_the_default_width() {
        let mut r = record();
        r.signals = [22u16, 23, 80, 443, 830, 8080, 8443]
            .into_iter()
            .map(Signal::OpenPort)
            .collect();
        let rendered = encode(&TableEncoder::default(), &[r]);
        assert_eq!(
            cells(rows(&rendered)[0])[PORTS],
            "22,23,80,443,830,8080,8443"
        );
    }

    #[test]
    fn the_last_column_runs_over_the_grid_rather_than_truncating() {
        let mut r = record();
        r.signals = (1u16..=40).map(|n| Signal::OpenPort(n * 100)).collect();
        let encoder = TableEncoder::new(MIN_TOTAL_WIDTH);
        let rendered = encode(&encoder, &[r]);
        let row = rows(&rendered)[0];
        assert!(!row.contains('…'), "row was {row:?}");
        assert!(row.ends_with(",4000"), "row was {row:?}");
    }

    #[test]
    fn no_line_carries_trailing_whitespace() {
        let mut r = named("access-sw-01");
        r.platform = Some("cisco_ios".into());
        r.signals.push(Signal::OpenPort(22));
        let rendered = encode(&TableEncoder::default(), &[r, record()]);
        for line in rendered.lines() {
            assert_eq!(line, line.trim_end(), "trailing whitespace on {line:?}");
        }
    }

    #[test]
    fn every_line_ends_with_a_newline() {
        let rendered = encode(&TableEncoder::default(), &[record(), record()]);
        assert!(rendered.ends_with('\n'));
    }

    #[test]
    fn an_oversized_cell_is_truncated_with_a_trailing_ellipsis() {
        let encoder = TableEncoder::new(MIN_TOTAL_WIDTH);
        let rendered = encode(&encoder, &[named(&"a".repeat(200))]);
        let name = cells(rows(&rendered)[0])[NAME].clone();
        assert_eq!(name.chars().count(), usize::from(COLUMNS[NAME].min));
        assert!(name.ends_with('…'), "name was {name:?}");
    }

    #[test]
    fn truncation_counts_characters_not_bytes() {
        // 20 CJK characters: 60 UTF-8 bytes, but only 20 characters against a 12-char cell.
        let encoder = TableEncoder::new(MIN_TOTAL_WIDTH);
        let rendered = encode(
            &encoder,
            &[named("以太网交换机制造商股份有限公司北京分公司")],
        );
        let name = cells(rows(&rendered)[0])[NAME].clone();
        assert_eq!(name.chars().count(), usize::from(COLUMNS[NAME].min));
        assert_eq!(name, "以太网交换机制造商股份…");
    }

    #[test]
    fn a_cell_that_exactly_fills_its_width_is_not_truncated() {
        let exact = "a".repeat(usize::from(COLUMNS[NAME].min));
        let encoder = TableEncoder::new(MIN_TOTAL_WIDTH);
        let rendered = encode(&encoder, &[named(&exact)]);
        assert_eq!(cells(rows(&rendered)[0])[NAME], exact);
    }

    #[test]
    fn layout_at_the_minimum_width_is_every_column_at_its_minimum() {
        let layout = TableLayout::for_total_width(MIN_TOTAL_WIDTH);
        let expected: Vec<u16> = COLUMNS.iter().map(|c| c.min).collect();
        assert_eq!(layout.widths(), expected.as_slice());
        assert_eq!(layout.total_width(), MIN_TOTAL_WIDTH);
    }

    #[rstest]
    #[case(0)]
    #[case(1)]
    #[case(40)]
    #[case(MIN_TOTAL_WIDTH - 1)]
    fn a_width_below_the_minimum_clamps_up_to_the_minimum(#[case] requested: u16) {
        let layout = TableLayout::for_total_width(requested);
        assert_eq!(layout.total_width(), MIN_TOTAL_WIDTH);
    }

    #[rstest]
    #[case(55)]
    #[case(67)]
    #[case(72)]
    #[case(80)]
    #[case(100)]
    #[case(120)]
    #[case(160)]
    #[case(200)]
    #[case(1000)]
    fn layout_never_exceeds_the_requested_width_and_never_breaks_a_column_bound(
        #[case] requested: u16,
    ) {
        let layout = TableLayout::for_total_width(requested);
        for (width, column) in layout.widths().iter().zip(COLUMNS.iter()) {
            assert!(
                *width >= column.min && *width <= column.max,
                "{} got {width}, bounds {}..={}",
                column.header,
                column.min,
                column.max
            );
        }
        assert!(
            layout.total_width() <= requested.max(MIN_TOTAL_WIDTH),
            "requested {requested}, laid out {}",
            layout.total_width()
        );
    }

    #[test]
    fn surplus_is_distributed_round_robin_one_character_at_a_time() {
        // Three characters of surplus land on the first three columns, not all on the first.
        let layout = TableLayout::for_total_width(MIN_TOTAL_WIDTH + 3);
        assert_eq!(layout.widths(), &[16, 13, 11, 12]);
    }

    #[test]
    fn the_default_width_lays_out_the_four_columns() {
        let layout = TableLayout::for_total_width(default_width());
        assert_eq!(layout.widths(), &[27, 24, 20, 23]);
        assert_eq!(layout.total_width(), 100);
    }

    #[test]
    fn a_column_at_its_maximum_is_skipped_while_the_others_keep_growing() {
        // PLATFORM saturates after 10 of the 70 surplus characters; the rest share what is left.
        let layout = TableLayout::for_total_width(MIN_TOTAL_WIDTH + 70);
        assert_eq!(layout.widths(), &[35, 32, 20, 32]);
        assert_eq!(layout.total_width(), MIN_TOTAL_WIDTH + 70);
    }

    #[test]
    fn the_grid_bounds_match_the_range_documented_on_encoder_config() {
        assert_eq!(MIN_TOTAL_WIDTH, 55);
        assert_eq!(MAX_TOTAL_WIDTH, 153);
    }

    #[test]
    fn a_width_beyond_the_sum_of_maximums_saturates_every_column() {
        let layout = TableLayout::for_total_width(10_000);
        let expected: Vec<u16> = COLUMNS.iter().map(|c| c.max).collect();
        assert_eq!(layout.widths(), expected.as_slice());
        assert_eq!(layout.total_width(), MAX_TOTAL_WIDTH);
    }

    #[test]
    fn header_and_rows_share_one_column_grid() {
        let encoder = TableEncoder::new(100);
        let mut r = named("access-sw-01");
        r.platform = Some("cisco_ios".into());
        r.signals.push(Signal::OpenPort(22));
        let rendered = encode(&encoder, &[r]);
        let mut lines = rendered.lines();
        let header = lines.next().expect("header");
        let row = lines.next().expect("row");
        let mut offset = 0usize;
        for width in encoder.layout().widths() {
            let column_start = offset;
            assert!(
                !header[column_start..].starts_with(' '),
                "header column at {column_start} is not left-aligned: {header:?}"
            );
            assert!(
                !row[column_start..].starts_with(' '),
                "row column at {column_start} is not left-aligned: {row:?}"
            );
            offset += usize::from(*width) + SEPARATOR.len();
        }
    }

    #[test]
    fn encode_link_writes_nothing() {
        use crate::model::{LinkEndpoint, LinkRecord, LINK_SCHEMA_ID};

        let link = LinkRecord {
            schema_version: LinkRecord::SCHEMA_VERSION.to_string(),
            schema_id: LINK_SCHEMA_ID.to_string(),
            a: LinkEndpoint {
                identity_key: None,
                chassis_id: "aabbccddeeff".into(),
                sys_name: None,
                port: "Gi0/1".into(),
            },
            b: LinkEndpoint {
                identity_key: None,
                chassis_id: "001122334455".into(),
                sys_name: None,
                port: "Gi0/2".into(),
            },
            discovered_via: "lldp".into(),
            observed_at: SystemTime::UNIX_EPOCH,
            scan_metadata: ScanMetadata::default(),
        };
        let mut buf = Vec::new();
        TableEncoder::default()
            .encode_link(&link, &mut buf)
            .expect("encode link");
        assert!(buf.is_empty(), "buffer was {buf:?}");
    }

    #[test]
    fn encode_profile_writes_nothing() {
        use crate::model::{
            Collection, CollectionProfileRecord, ProfileConfidence, ProfileEndpoint, Transport,
            COLLECTION_PROFILE_SCHEMA_ID,
        };

        let profile = CollectionProfileRecord {
            schema_version: CollectionProfileRecord::SCHEMA_VERSION.to_string(),
            schema_id: COLLECTION_PROFILE_SCHEMA_ID.to_string(),
            identity_key: "ip:10.0.0.1".into(),
            endpoint: ProfileEndpoint {
                address: "10.0.0.1".into(),
                port: 57400,
                transport: Transport::Tls,
            },
            confidence: ProfileConfidence::AdvertisedOnly,
            note: None,
            collection: Collection::Gnmi {
                gnmi_version: Some("0.10.0".into()),
                encoding: "JSON_IETF".into(),
                supported_models: Vec::new(),
                suggested_subscriptions: Vec::new(),
            },
            observed_at: SystemTime::UNIX_EPOCH,
            scan_metadata: ScanMetadata::default(),
        };
        let mut buf = Vec::new();
        TableEncoder::default()
            .encode_profile(&profile, &mut buf)
            .expect("encode profile");
        assert!(buf.is_empty(), "buffer was {buf:?}");
    }

    #[test]
    fn table_encoder_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TableEncoder>();
    }

    #[test]
    fn default_width_is_one_hundred() {
        assert_eq!(default_width(), 100);
        assert_eq!(TableEncoder::default().layout().total_width(), 100);
    }

    #[test]
    fn renders_a_representative_scan() {
        let mut cloudflare = record();
        cloudflare.identity_key = IdentityKey::new("ip:1.1.1.1").expect("identity");
        cloudflare.mgmt_ip = Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        cloudflare.signals = vec![
            Signal::OpenPort(80),
            Signal::OpenPort(443),
            Signal::OpenPort(8080),
            Signal::OpenPort(8443),
            Signal::ReverseDnsName("one.one.one.one".into()),
        ];

        let mut switch = record();
        switch.identity_key = IdentityKey::new("ip:198.51.100.11").expect("identity");
        switch.mgmt_ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11)));
        switch.manufacturer = Some("Cisco Systems".into());
        switch.platform = Some("cisco_ios".into());
        switch.signals = vec![
            Signal::OpenPort(22),
            Signal::OpenPort(443),
            Signal::SnmpSysName("access-sw-01".into()),
        ];

        let dark = record();

        let rendered = encode(&TableEncoder::new(100), &[cloudflare, switch, dark]);
        insta::assert_snapshot!(rendered);
    }
}
