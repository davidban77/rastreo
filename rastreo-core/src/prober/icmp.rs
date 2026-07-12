use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
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

use crate::error::{ConfigError, ProbeErrorKind, RastreoError, RuntimeError};
use crate::model::{ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::classify::{self, Disposition};
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

static NONCE_SEED: LazyLock<u64> = LazyLock::new(|| {
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
    // Concurrent processes share the kernel echo-id space, so keep their nonce streams disjoint
    // structurally rather than by clock luck.
    let pid_hash = (std::process::id() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    now_nanos ^ elapsed_nanos.rotate_left(17) ^ tid_hash.rotate_left(31) ^ pid_hash
});

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

// Bijective in `ticket`, so two in-flight probes can never share a nonce and cross-demux replies.
fn generate_nonce() -> [u8; PAYLOAD_NONCE_LEN] {
    let ticket = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut state = NONCE_SEED.wrapping_add(ticket.wrapping_mul(0x9e37_79b9_7f4a_7c15));
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

fn open_socket(target: IpAddr) -> Result<Socket, ProbeFault> {
    let (domain, protocol) = match target {
        IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4),
        IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6),
    };

    let socket = match Socket::new(domain, Type::DGRAM, Some(protocol)) {
        Ok(s) => s,
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            Socket::new(domain, Type::RAW, Some(protocol)).map_err(|e| {
                ProbeFault::new(
                    ProbeErrorKind::PermissionDenied,
                    format!("icmp: raw socket unavailable: {e}"),
                )
            })?
        }
        Err(err) => {
            return Err(ProbeFault::new(
                ProbeErrorKind::Other,
                format!("icmp: dgram socket open failed: {err}"),
            ))
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

/// What the ping loop has learned so far, readable while the loop is still running.
#[derive(Debug, Clone, Default)]
struct Evidence {
    started: bool,
    rtts: Vec<Duration>,
    fault: Option<ProbeFault>,
}

/// Readable by the async caller after it abandons the blocking ping thread at its own deadline.
type EvidenceSlot = Arc<Mutex<Evidence>>;

fn mark_started(slot: &EvidenceSlot) {
    let mut guard = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.started = true;
}

fn push_rtt(slot: &EvidenceSlot, rtt: Duration) {
    let mut guard = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.rtts.push(rtt);
}

fn latch_fault(slot: &EvidenceSlot, fault: ProbeFault) {
    let mut guard = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.fault = Some(fault);
}

fn collected(slot: &EvidenceSlot) -> Evidence {
    slot.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

// An echo reply already in hand outranks a fault on a later packet: the host answered.
fn fault_when_unanswered(rtts: &[Duration], fault: Option<ProbeFault>) -> Option<ProbeFault> {
    if rtts.is_empty() {
        fault
    } else {
        None
    }
}

type BlockingOutcome =
    Result<Result<Vec<Duration>, tokio::task::JoinError>, tokio::time::error::Elapsed>;

fn fold_probe_outcome(
    outcome: BlockingOutcome,
    slot: &EvidenceSlot,
) -> Result<Vec<Duration>, RastreoError> {
    match outcome {
        Ok(Ok(rtts)) => Ok(rtts),
        Ok(Err(join_err)) => Err(RastreoError::Runtime(RuntimeError::TaskPanicked(
            join_err.to_string(),
        ))),
        // The ping loop outlived our deadline: keep what it had already learned.
        Err(_) => {
            let evidence = collected(slot);
            if !evidence.started {
                // The pool never ran the closure: nothing was learned, so latch a fault.
                latch_fault(
                    slot,
                    ProbeFault::new(
                        ProbeErrorKind::Other,
                        "icmp: probe did not start before the deadline".to_string(),
                    ),
                );
            }
            Ok(evidence.rtts)
        }
    }
}

fn run_probe_blocking(
    target: IpAddr,
    count: u32,
    interval: Duration,
    deadline: Instant,
    slot: &EvidenceSlot,
) -> Vec<Duration> {
    mark_started(slot);
    let socket = match open_socket(target) {
        Ok(s) => s,
        Err(fault) => {
            latch_fault(slot, fault);
            return Vec::new();
        }
    };
    if let Err(err) = socket.set_nonblocking(false) {
        latch_fault(
            slot,
            ProbeFault::new(
                ProbeErrorKind::Other,
                format!("icmp: set_nonblocking failed: {err}"),
            ),
        );
        return Vec::new();
    }
    ping_loop(&socket, target, count, interval, deadline, slot)
}

fn ping_loop(
    socket: &Socket,
    target: IpAddr,
    count: u32,
    interval: Duration,
    deadline: Instant,
    slot: &EvidenceSlot,
) -> Vec<Duration> {
    let dest: SocketAddr = match target {
        IpAddr::V4(v4) => SocketAddr::from((v4, 0)),
        IpAddr::V6(v6) => SocketAddr::from((v6, 0)),
    };
    let dest_sock = socket2::SockAddr::from(dest);

    let identifier: u16 = 0;
    let nonce = generate_nonce();
    let reference = Instant::now();
    let per_packet_budget = deadline.saturating_duration_since(reference) / count.max(1);

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
            // A dark host latches EHOSTUNREACH / ENETUNREACH on the socket: no reply, not a fault.
            if let Disposition::Fault(kind) = classify::io_error(&err) {
                latch_fault(
                    slot,
                    ProbeFault::new(kind, format!("icmp: send failed: {err}")),
                );
            }
            break;
        }

        let per_pkt_deadline = (send_at + per_packet_budget).min(deadline);
        match recv_matching_reply(socket, target, &nonce, max_seq, per_pkt_deadline) {
            Ok(Some(sent_offset)) => {
                let now = Instant::now();
                let elapsed = now.saturating_duration_since(reference);
                push_rtt(slot, elapsed.saturating_sub(sent_offset));
            }
            Ok(None) => {}
            Err(err) => {
                if let Disposition::Fault(kind) = classify::io_error(&err) {
                    latch_fault(
                        slot,
                        ProbeFault::new(kind, format!("icmp: recv failed: {err}")),
                    );
                }
                break;
            }
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

    collected(slot).rtts
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
        // Set before the spawn so a queued closure cannot outlive the timer below.
        let deadline = Instant::now() + ctx.timeout;

        let evidence: EvidenceSlot = Arc::default();
        let sink = Arc::clone(&evidence);

        let outcome = timeout(
            ctx.timeout,
            tokio::task::spawn_blocking(move || {
                run_probe_blocking(target_ip, count, interval, deadline, &sink)
            }),
        )
        .await;

        let rtts = fold_probe_outcome(outcome, &evidence)?;
        let fault = fault_when_unanswered(&rtts, collected(&evidence).fault);

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
            fault,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

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
        let mut seen = HashSet::new();
        for _ in 0..100_000 {
            let nonce = generate_nonce();
            assert!(
                seen.insert(nonce),
                "nonce repeated within one thread: {nonce:?}"
            );
        }
    }

    #[test]
    fn generate_nonce_produces_distinct_values_across_threads() {
        const THREADS: usize = 8;
        const PER_THREAD: usize = 10_000;

        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                std::thread::spawn(|| {
                    (0..PER_THREAD)
                        .map(|_| generate_nonce())
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        let mut seen = HashSet::new();
        for worker in workers {
            for nonce in worker.join().expect("worker thread panicked") {
                assert!(
                    seen.insert(nonce),
                    "nonce repeated across threads: {nonce:?}"
                );
            }
        }
        assert_eq!(seen.len(), THREADS * PER_THREAD);
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
    fn a_send_that_fails_locally_is_a_probe_fault_not_a_silent_host() {
        // An AF_INET socket cannot send to an IPv6 destination, so the send fails in the kernel
        // before a packet leaves the host — the same shape as an ICMP send denied locally, and
        // reachable without CAP_NET_RAW.
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("socket");
        socket.set_nonblocking(false).expect("blocking socket");
        let target: IpAddr = "2001:db8::1".parse().expect("valid ipv6");
        let slot: EvidenceSlot = Arc::default();

        let rtts = ping_loop(
            &socket,
            target,
            1,
            Duration::ZERO,
            Instant::now() + Duration::from_millis(200),
            &slot,
        );
        assert!(rtts.is_empty(), "a send that failed learned no rtt");
        let fault = collected(&slot).fault.expect(
            "a send the classifier calls a fault must be latched, not booked as a dark host",
        );
        assert!(
            fault.detail.contains("icmp: send failed"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn run_probe_blocking_marks_the_slot_started_before_it_touches_a_socket() {
        let slot: EvidenceSlot = Arc::default();

        let _ = run_probe_blocking(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            1,
            Duration::ZERO,
            Instant::now(),
            &slot,
        );

        assert!(
            collected(&slot).started,
            "the caller cannot tell a probe that never ran from a host that never answered \
             unless the closure publishes that it ran"
        );
    }

    #[test]
    fn a_socket_fault_is_latched_before_it_leaves_the_blocking_thread() {
        let slot: EvidenceSlot = Arc::default();

        latch_fault(
            &slot,
            ProbeFault::new(
                ProbeErrorKind::Other,
                "icmp: dgram socket open failed: too many open files".to_string(),
            ),
        );

        let fault = collected(&slot)
            .fault
            .expect("a caller that abandons the thread must still see the fault it hit");
        assert!(
            fault.detail.contains("icmp: dgram socket open failed"),
            "got: {}",
            fault.detail
        );
    }

    fn sample_fault(detail: &str) -> ProbeFault {
        ProbeFault::new(ProbeErrorKind::Other, detail.to_string())
    }

    #[test]
    fn an_echo_reply_outranks_a_later_send_fault() {
        let fault = fault_when_unanswered(
            &[Duration::from_micros(1_200)],
            Some(sample_fault("icmp: send failed: no buffer space available")),
        );
        assert!(
            fault.is_none(),
            "a host that answered a ping drops a later fault"
        );
    }

    #[test]
    fn no_reply_and_a_fault_surfaces_the_fault() {
        let fault =
            fault_when_unanswered(&[], Some(sample_fault("icmp: recv failed: interrupted")))
                .expect("a broken probe surfaces its fault");
        assert!(
            fault.detail.contains("icmp: recv failed"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn no_reply_and_no_fault_is_an_absent_target() {
        assert!(fault_when_unanswered(&[], None).is_none());
    }

    async fn elapsed() -> tokio::time::error::Elapsed {
        timeout(Duration::ZERO, std::future::pending::<()>())
            .await
            .expect_err("a zero deadline on a pending future always elapses")
    }

    #[test]
    fn a_probe_that_finishes_inside_the_deadline_returns_its_rtts() {
        let slot: EvidenceSlot = Arc::default();
        let rtts = fold_probe_outcome(Ok(Ok(vec![Duration::from_micros(900)])), &slot)
            .expect("a completed probe is an outcome");
        assert_eq!(rtts, vec![Duration::from_micros(900)]);
    }

    #[tokio::test]
    async fn a_deadline_that_fires_after_a_reply_keeps_the_rtt() {
        // A host behind an ICMP policer answers the first echo, drops the rest, and runs the loop
        // past the caller's deadline.
        let slot: EvidenceSlot = Arc::default();
        mark_started(&slot);
        push_rtt(&slot, Duration::from_micros(1_500));

        let rtts = fold_probe_outcome(Err(elapsed().await), &slot)
            .expect("a host that answered before the deadline is not a dark host");
        assert_eq!(rtts, vec![Duration::from_micros(1_500)]);
    }

    #[tokio::test]
    async fn a_deadline_that_fires_with_nothing_learned_is_an_absent_target() {
        let slot: EvidenceSlot = Arc::default();
        mark_started(&slot);

        let rtts = fold_probe_outcome(Err(elapsed().await), &slot)
            .expect("a silent host is an outcome, not an error");
        assert!(rtts.is_empty());
    }

    #[tokio::test]
    async fn a_deadline_that_fires_before_the_probe_starts_latches_a_fault() {
        // A backed-up blocking pool never runs the closure: the target was never asked anything.
        let slot: EvidenceSlot = Arc::default();

        let rtts = fold_probe_outcome(Err(elapsed().await), &slot)
            .expect("a probe that never ran carries its fault on the outcome, not as an Err");
        assert!(rtts.is_empty());
        let fault = collected(&slot)
            .fault
            .expect("a probe that never ran latches a fault");
        assert!(
            fault.detail.contains("did not start"),
            "got: {}",
            fault.detail
        );
    }

    #[tokio::test]
    async fn a_deadline_that_fires_after_a_latched_fault_keeps_the_fault() {
        let slot: EvidenceSlot = Arc::default();
        mark_started(&slot);
        latch_fault(&slot, sample_fault("icmp: recv failed: interrupted"));

        let rtts = fold_probe_outcome(Err(elapsed().await), &slot)
            .expect("a broken probe carries its fault on the outcome, not as an Err");
        assert!(rtts.is_empty());
        let fault = collected(&slot).fault.expect("the latched fault survives");
        assert!(
            fault.detail.contains("icmp: recv failed"),
            "got: {}",
            fault.detail
        );
    }

    #[tokio::test]
    async fn a_panicked_ping_thread_is_a_runtime_error() {
        let join_err = tokio::task::spawn_blocking(|| panic!("ping thread died"))
            .await
            .expect_err("the task panicked");
        let slot: EvidenceSlot = Arc::default();

        let err = fold_probe_outcome(Ok(Err(join_err)), &slot)
            .expect_err("a dead probe thread is a runtime error, not a dark host");
        assert!(
            matches!(err, RastreoError::Runtime(RuntimeError::TaskPanicked(_))),
            "got: {err:?}"
        );
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

    #[test]
    #[cfg_attr(
        not(target_os = "macos"),
        ignore = "requires Linux ping_group_range sysctl or CAP_NET_RAW"
    )]
    fn a_live_ping_loop_publishes_each_rtt_before_it_returns() {
        // The caller reads this slot after abandoning the loop at its own deadline, so a reply is
        // only safe once it is in there — not when the loop finally returns it.
        use std::net::Ipv4Addr;

        let socket = open_socket(IpAddr::V4(Ipv4Addr::LOCALHOST)).expect("icmp socket");
        socket.set_nonblocking(false).expect("blocking socket");
        let slot: EvidenceSlot = Arc::default();

        let returned = ping_loop(
            &socket,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            2,
            Duration::ZERO,
            Instant::now() + Duration::from_secs(2),
            &slot,
        );

        let published = collected(&slot).rtts;
        assert!(
            !published.is_empty(),
            "loopback answered, so the slot must hold its rtt"
        );
        assert_eq!(
            published, returned,
            "what the loop publishes and what it returns must not diverge"
        );
    }
}
