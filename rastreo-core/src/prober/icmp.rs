use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pnet_packet::icmp::echo_reply::EchoReplyPacket;
use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet_packet::icmp::{checksum as icmp_checksum, IcmpPacket, IcmpTypes};
use pnet_packet::icmpv6::echo_reply::EchoReplyPacket as Icmpv6EchoReplyPacket;
use pnet_packet::icmpv6::echo_request::MutableEchoRequestPacket as MutableIcmpv6EchoRequestPacket;
use pnet_packet::icmpv6::Icmpv6Types;
use pnet_packet::Packet;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::time::timeout;

use crate::error::{ConfigError, ProbeError, RastreoError};
use crate::model::{ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::Prober;

const PAYLOAD_NONCE_LEN: usize = 8;
const PAYLOAD_TIMESTAMP_LEN: usize = 8;
const PAYLOAD_MARKER: &[u8; 16] = b"rastreo-icmp-v01";
const PAYLOAD_LEN: usize = PAYLOAD_NONCE_LEN + PAYLOAD_TIMESTAMP_LEN + PAYLOAD_MARKER.len();
const ICMP_HEADER_LEN: usize = 8;
const ICMP_PACKET_LEN: usize = ICMP_HEADER_LEN + PAYLOAD_LEN;
const RECV_BUF_LEN: usize = 2048;
const MAX_COUNT: u32 = 1024;

pub struct IcmpProber {
    count: u32,
    interval: Duration,
}

impl IcmpProber {
    pub fn new(count: u32, interval_ms: u64) -> Result<Self, RastreoError> {
        if count == 0 {
            return Err(ConfigError::invalid("icmp prober requires count >= 1").into());
        }
        if count > MAX_COUNT {
            return Err(ConfigError::invalid("icmp prober count must be <= 1024").into());
        }
        Ok(Self {
            count,
            interval: Duration::from_millis(interval_ms),
        })
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }
}

pub fn default_count() -> u32 {
    3
}

pub fn default_interval_ms() -> u64 {
    200
}

fn generate_nonce() -> [u8; PAYLOAD_NONCE_LEN] {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let elapsed_nanos = Instant::now().elapsed().as_nanos() as u64;
    let tid = format!("{:?}", std::thread::current().id());
    let mut tid_hash: u64 = 0xcbf29ce484222325;
    for b in tid.as_bytes() {
        tid_hash ^= *b as u64;
        tid_hash = tid_hash.wrapping_mul(0x100000001b3);
    }
    let mut state = now_nanos ^ elapsed_nanos.rotate_left(17) ^ tid_hash.rotate_left(31);
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state.to_le_bytes()
}

fn encode_timestamp_micros(reference: Instant, at: Instant) -> [u8; PAYLOAD_TIMESTAMP_LEN] {
    let micros = at.saturating_duration_since(reference).as_micros() as u64;
    micros.to_le_bytes()
}

fn decode_timestamp_micros(bytes: &[u8]) -> Option<u64> {
    let arr: [u8; PAYLOAD_TIMESTAMP_LEN] = bytes.try_into().ok()?;
    Some(u64::from_le_bytes(arr))
}

fn build_payload(
    nonce: &[u8; PAYLOAD_NONCE_LEN],
    reference: Instant,
    at: Instant,
) -> [u8; PAYLOAD_LEN] {
    let mut payload = [0u8; PAYLOAD_LEN];
    payload[..PAYLOAD_NONCE_LEN].copy_from_slice(nonce);
    payload[PAYLOAD_NONCE_LEN..PAYLOAD_NONCE_LEN + PAYLOAD_TIMESTAMP_LEN]
        .copy_from_slice(&encode_timestamp_micros(reference, at));
    payload[PAYLOAD_NONCE_LEN + PAYLOAD_TIMESTAMP_LEN..].copy_from_slice(PAYLOAD_MARKER);
    payload
}

pub(crate) fn build_icmpv4_echo_request(
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> [u8; ICMP_PACKET_LEN] {
    let mut buf = [0u8; ICMP_PACKET_LEN];
    {
        let mut pkt = MutableEchoRequestPacket::new(&mut buf)
            .expect("buffer sized to icmp echo request length");
        pkt.set_icmp_type(IcmpTypes::EchoRequest);
        pkt.set_icmp_code(pnet_packet::icmp::echo_request::IcmpCodes::NoCode);
        pkt.set_identifier(identifier);
        pkt.set_sequence_number(sequence);
        pkt.set_payload(payload);
    }
    let cksum = {
        let view = IcmpPacket::new(&buf).expect("icmp view over sized buffer");
        icmp_checksum(&view)
    };
    let bytes = cksum.to_be_bytes();
    buf[2] = bytes[0];
    buf[3] = bytes[1];
    buf
}

pub(crate) fn build_icmpv6_echo_request(
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> [u8; ICMP_PACKET_LEN] {
    let mut buf = [0u8; ICMP_PACKET_LEN];
    let mut pkt = MutableIcmpv6EchoRequestPacket::new(&mut buf)
        .expect("buffer sized to icmpv6 echo request length");
    pkt.set_icmpv6_type(Icmpv6Types::EchoRequest);
    pkt.set_icmpv6_code(pnet_packet::icmpv6::echo_request::Icmpv6Codes::NoCode);
    pkt.set_identifier(identifier);
    pkt.set_sequence_number(sequence);
    pkt.set_payload(payload);
    buf
}

fn open_socket(target: IpAddr) -> Result<Socket, RastreoError> {
    let (domain, protocol) = match target {
        IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4),
        IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6),
    };

    let socket = match Socket::new(domain, Type::DGRAM, Some(protocol)) {
        Ok(s) => s,
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            Socket::new(domain, Type::RAW, Some(protocol))
                .map_err(|e| ProbeError::Other(format!("icmp: raw socket unavailable: {e}")))?
        }
        Err(err) => {
            return Err(ProbeError::Other(format!("icmp: dgram socket open failed: {err}")).into())
        }
    };

    Ok(socket)
}

fn recv_matching_reply(
    socket: &Socket,
    target: IpAddr,
    nonce: &[u8; PAYLOAD_NONCE_LEN],
    max_sequence: u16,
    deadline: Instant,
) -> Result<Option<Duration>, std::io::Error> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        let remaining = deadline - now;
        socket.set_read_timeout(Some(remaining))?;

        let mut buf = [MaybeUninit::<u8>::uninit(); RECV_BUF_LEN];
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                if from.as_socket().map(|s| s.ip()) != Some(target) {
                    continue;
                }
                let bytes: &[u8] =
                    unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                if let Some(rtt) = match_reply(target, bytes, nonce, max_sequence) {
                    return Ok(Some(rtt));
                }
            }
            Err(err) => match err.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut => return Ok(None),
                _ => return Err(err),
            },
        }
    }
}

fn ipv4_header_len(bytes: &[u8]) -> Option<usize> {
    let first = *bytes.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let ihl_words = (first & 0x0f) as usize;
    if ihl_words < 5 {
        return None;
    }
    Some(ihl_words * 4)
}

fn match_reply(
    target: IpAddr,
    bytes: &[u8],
    nonce: &[u8; PAYLOAD_NONCE_LEN],
    max_sequence: u16,
) -> Option<Duration> {
    match target {
        IpAddr::V4(_) => {
            let ip_stripped = bytes;
            let raw_stripped = ipv4_header_len(bytes)
                .and_then(|len| bytes.get(len..))
                .unwrap_or(&[]);
            let candidates: [&[u8]; 2] = [ip_stripped, raw_stripped];
            for slice in candidates {
                if let Some(reply) = EchoReplyPacket::new(slice) {
                    if reply.get_icmp_type() != IcmpTypes::EchoReply {
                        continue;
                    }
                    if reply.get_sequence_number() > max_sequence {
                        continue;
                    }
                    if let Some(rtt) = payload_rtt(reply.payload(), nonce) {
                        return Some(rtt);
                    }
                }
            }
            None
        }
        IpAddr::V6(_) => {
            let reply = Icmpv6EchoReplyPacket::new(bytes)?;
            if reply.get_icmpv6_type() != Icmpv6Types::EchoReply {
                return None;
            }
            if reply.get_sequence_number() > max_sequence {
                return None;
            }
            payload_rtt(reply.payload(), nonce)
        }
    }
}

fn payload_rtt(payload: &[u8], nonce: &[u8; PAYLOAD_NONCE_LEN]) -> Option<Duration> {
    if payload.len() < PAYLOAD_LEN {
        return None;
    }
    if &payload[..PAYLOAD_NONCE_LEN] != nonce.as_slice() {
        return None;
    }
    let ts_start = PAYLOAD_NONCE_LEN;
    let ts_end = ts_start + PAYLOAD_TIMESTAMP_LEN;
    if &payload[ts_end..ts_end + PAYLOAD_MARKER.len()] != PAYLOAD_MARKER.as_slice() {
        return None;
    }
    let sent_micros = decode_timestamp_micros(&payload[ts_start..ts_end])?;
    Some(Duration::from_micros(sent_micros))
}

fn run_probe_blocking(
    target: IpAddr,
    count: u32,
    interval: Duration,
    total_timeout: Duration,
) -> Result<Vec<Duration>, RastreoError> {
    let socket = open_socket(target)?;
    socket
        .set_nonblocking(false)
        .map_err(|e| ProbeError::Other(format!("icmp: set_nonblocking failed: {e}")))?;

    let dest: SocketAddr = match target {
        IpAddr::V4(v4) => SocketAddr::from((v4, 0)),
        IpAddr::V6(v6) => SocketAddr::from((v6, 0)),
    };
    let dest_sock = socket2::SockAddr::from(dest);

    let identifier: u16 = 0;
    let nonce = generate_nonce();
    let reference = Instant::now();
    let deadline = reference + total_timeout;
    let per_packet_budget = total_timeout / count.max(1);

    let mut rtts: Vec<Duration> = Vec::with_capacity(count as usize);
    let max_seq = count.saturating_sub(1).min(u16::MAX as u32) as u16;

    for seq in 0..count {
        if Instant::now() >= deadline {
            break;
        }
        let send_at = Instant::now();
        let payload = build_payload(&nonce, reference, send_at);
        let packet = match target {
            IpAddr::V4(_) => build_icmpv4_echo_request(identifier, seq as u16, &payload),
            IpAddr::V6(_) => build_icmpv6_echo_request(identifier, seq as u16, &payload),
        };

        if let Err(err) = socket.send_to(&packet, &dest_sock) {
            return Err(ProbeError::Other(format!("icmp: send failed: {err}")).into());
        }

        let per_pkt_deadline = (send_at + per_packet_budget).min(deadline);
        match recv_matching_reply(&socket, target, &nonce, max_seq, per_pkt_deadline) {
            Ok(Some(sent_offset)) => {
                let now = Instant::now();
                let elapsed = now.saturating_duration_since(reference);
                let rtt = elapsed.saturating_sub(sent_offset);
                rtts.push(rtt);
            }
            Ok(None) => {}
            Err(err) => return Err(ProbeError::Other(format!("icmp: recv failed: {err}")).into()),
        }

        if seq + 1 < count && !interval.is_zero() {
            let now = Instant::now();
            let sleep_until = now + interval;
            if sleep_until >= deadline {
                break;
            }
            std::thread::sleep(interval);
        }
    }

    Ok(rtts)
}

#[async_trait::async_trait]
impl Prober for IcmpProber {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Icmp
    }

    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError> {
        let target_ip = target.ip;
        let count = self.count;
        let interval = self.interval;
        let total_timeout = ctx.timeout;

        let outcome = timeout(
            ctx.timeout,
            tokio::task::spawn_blocking(move || {
                run_probe_blocking(target_ip, count, interval, total_timeout)
            }),
        )
        .await;

        let rtts = match outcome {
            Ok(Ok(Ok(rtts))) => rtts,
            Ok(Ok(Err(err))) => return Err(err),
            Ok(Err(join_err)) => {
                return Err(RastreoError::Runtime(
                    crate::error::RuntimeError::TaskPanicked(join_err.to_string()),
                ))
            }
            Err(_) => Vec::new(),
        };

        let (reachable, signals) = if rtts.is_empty() {
            (false, Vec::new())
        } else {
            let min = rtts
                .iter()
                .min()
                .copied()
                .unwrap_or_else(|| Duration::from_micros(0));
            (
                true,
                vec![Signal::IcmpEchoRttMicros(min.as_micros() as u64)],
            )
        };

        Ok(ProbeOutcome {
            kind: ProbeKind::Icmp,
            target_ip: target.ip,
            timestamp: SystemTime::now(),
            reachable,
            signals,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_zero_count() {
        match IcmpProber::new(0, 200) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("count"), "got: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("zero count must error"),
        }
    }

    #[test]
    fn new_accepts_count_one() {
        let p = IcmpProber::new(1, 50).expect("valid");
        assert_eq!(p.count(), 1);
    }

    #[test]
    fn new_accepts_count_at_max() {
        let p = IcmpProber::new(MAX_COUNT, 50).expect("valid");
        assert_eq!(p.count(), MAX_COUNT);
    }

    #[test]
    fn new_rejects_count_over_1024() {
        match IcmpProber::new(1025, 200) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("1024"), "got: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("count over 1024 must error"),
        }
    }

    #[test]
    fn new_stores_interval_from_ms() {
        let p = IcmpProber::new(3, 250).expect("valid");
        assert_eq!(p.interval(), Duration::from_millis(250));
    }

    #[test]
    fn new_accepts_zero_interval() {
        let p = IcmpProber::new(2, 0).expect("valid");
        assert_eq!(p.interval(), Duration::ZERO);
    }

    #[test]
    fn default_count_is_three() {
        assert_eq!(default_count(), 3);
    }

    #[test]
    fn default_interval_ms_is_two_hundred() {
        assert_eq!(default_interval_ms(), 200);
    }

    #[test]
    fn probe_kind_returns_icmp() {
        let p = IcmpProber::new(3, 200).expect("valid");
        assert_eq!(p.kind(), ProbeKind::Icmp);
    }

    #[test]
    fn payload_timestamp_round_trips() {
        let reference = Instant::now();
        let later = reference + Duration::from_micros(1_234_567);
        let encoded = encode_timestamp_micros(reference, later);
        let decoded = decode_timestamp_micros(&encoded).expect("decoded");
        assert_eq!(decoded, 1_234_567);
    }

    #[test]
    fn build_payload_contains_nonce_timestamp_and_marker() {
        let reference = Instant::now();
        let later = reference + Duration::from_micros(4_242);
        let nonce = [0xa5u8; PAYLOAD_NONCE_LEN];
        let payload = build_payload(&nonce, reference, later);
        assert_eq!(&payload[..PAYLOAD_NONCE_LEN], nonce.as_slice());
        let ts_start = PAYLOAD_NONCE_LEN;
        let ts_end = ts_start + PAYLOAD_TIMESTAMP_LEN;
        let ts = decode_timestamp_micros(&payload[ts_start..ts_end]).expect("decoded");
        assert_eq!(ts, 4_242);
        assert_eq!(&payload[ts_end..], PAYLOAD_MARKER.as_slice());
    }

    #[test]
    fn payload_rtt_recovers_send_offset() {
        let reference = Instant::now();
        let sent = reference + Duration::from_micros(9_999);
        let nonce = [0x11u8; PAYLOAD_NONCE_LEN];
        let payload = build_payload(&nonce, reference, sent);
        let recovered = payload_rtt(&payload, &nonce).expect("payload matches nonce");
        assert_eq!(recovered, Duration::from_micros(9_999));
    }

    #[test]
    fn payload_rtt_rejects_mismatched_nonce() {
        let nonce = [0x22u8; PAYLOAD_NONCE_LEN];
        let other_nonce = [0x33u8; PAYLOAD_NONCE_LEN];
        let payload = build_payload(&nonce, Instant::now(), Instant::now());
        assert!(payload_rtt(&payload, &other_nonce).is_none());
    }

    #[test]
    fn payload_rtt_rejects_corrupted_marker() {
        let nonce = [0x44u8; PAYLOAD_NONCE_LEN];
        let mut payload = build_payload(&nonce, Instant::now(), Instant::now());
        let marker_start = PAYLOAD_NONCE_LEN + PAYLOAD_TIMESTAMP_LEN;
        payload[marker_start] ^= 0xff;
        assert!(payload_rtt(&payload, &nonce).is_none());
    }

    #[test]
    fn generate_nonce_produces_distinct_values() {
        let a = generate_nonce();
        let b = generate_nonce();
        assert_ne!(a, b, "two consecutive nonces should differ");
    }

    #[test]
    fn checksum_matches_expected_for_known_payload() {
        let nonce = [0u8; PAYLOAD_NONCE_LEN];
        let payload = build_payload(&nonce, Instant::now(), Instant::now());
        let packet = build_icmpv4_echo_request(0x1234, 0x0001, &payload);
        assert_eq!(packet[0], 8);
        assert_eq!(packet[1], 0);
        let stored_cksum = u16::from_be_bytes([packet[2], packet[3]]);
        let mut cleared = packet;
        cleared[2] = 0;
        cleared[3] = 0;
        let view = IcmpPacket::new(&cleared).expect("view");
        let recomputed = icmp_checksum(&view);
        assert_eq!(stored_cksum, recomputed);
        assert_ne!(stored_cksum, 0);
    }

    #[test]
    fn ipv4_header_len_computes_from_ihl() {
        let mut hdr = [0u8; 24];
        hdr[0] = 0x46;
        assert_eq!(ipv4_header_len(&hdr), Some(24));
        hdr[0] = 0x45;
        assert_eq!(ipv4_header_len(&hdr), Some(20));
        hdr[0] = 0x60;
        assert_eq!(ipv4_header_len(&hdr), None);
        hdr[0] = 0x44;
        assert_eq!(ipv4_header_len(&hdr), None);
    }

    #[test]
    fn icmpv4_echo_request_identifier_and_sequence_are_encoded_big_endian() {
        let payload = [0u8; PAYLOAD_LEN];
        let packet = build_icmpv4_echo_request(0xabcd, 0x1234, &payload);
        let identifier = u16::from_be_bytes([packet[4], packet[5]]);
        let sequence = u16::from_be_bytes([packet[6], packet[7]]);
        assert_eq!(identifier, 0xabcd);
        assert_eq!(sequence, 0x1234);
    }

    #[test]
    fn icmpv6_echo_request_type_is_128_and_code_is_zero() {
        let payload = [0u8; PAYLOAD_LEN];
        let packet = build_icmpv6_echo_request(0x1234, 0x5678, &payload);
        assert_eq!(packet[0], 128);
        assert_eq!(packet[1], 0);
        let identifier = u16::from_be_bytes([packet[4], packet[5]]);
        let sequence = u16::from_be_bytes([packet[6], packet[7]]);
        assert_eq!(identifier, 0x1234);
        assert_eq!(sequence, 0x5678);
    }

    #[test]
    fn icmp_prober_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<IcmpProber>();
        assert_send_sync::<Box<dyn Prober>>();
    }

    #[tokio::test]
    #[cfg_attr(
        not(target_os = "macos"),
        ignore = "requires Linux ping_group_range sysctl or CAP_NET_RAW"
    )]
    async fn live_probe_loopback_returns_signal() {
        use crate::model::Target;
        use std::net::Ipv4Addr;

        let prober = IcmpProber::new(3, 50).expect("valid");
        let ctx = ProbeCtx {
            timeout: Duration::from_secs(2),
            retries: 0,
        };
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let target = ResolvedTarget {
            ip,
            original: Target::Ip(ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        };
        let outcome = prober.probe(&target, &ctx).await.expect("probe ok");
        assert!(outcome.reachable, "loopback should be reachable");
        assert_eq!(outcome.signals.len(), 1, "expected exactly one signal");
        assert!(
            matches!(outcome.signals.first(), Some(Signal::IcmpEchoRttMicros(_))),
            "expected IcmpEchoRttMicros signal, got {:?}",
            outcome.signals
        );
    }
}
