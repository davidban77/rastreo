use std::collections::HashMap;
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
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::task::AbortHandle;
use tokio::time::{timeout_at, Instant as TokioInstant};

use crate::error::{ConfigError, ProbeErrorKind, RastreoError};
use crate::model::{ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::classify::{self, Disposition};
use crate::prober::demux::{Demux, EngineReply};
use crate::prober::Prober;

const PAYLOAD_NONCE_LEN: usize = 8;
const PAYLOAD_TIMESTAMP_LEN: usize = 8;
const PAYLOAD_MARKER: &[u8; 16] = b"rastreo-icmp-v01";
const PAYLOAD_LEN: usize = PAYLOAD_NONCE_LEN + PAYLOAD_TIMESTAMP_LEN + PAYLOAD_MARKER.len();
const ICMP_HEADER_LEN: usize = 8;
const ICMP_PACKET_LEN: usize = ICMP_HEADER_LEN + PAYLOAD_LEN;
const RECV_BUF_LEN: usize = 2048;
// Generous so a wide scan's reply burst queues instead of overflowing the shared socket; kernel clamps to rmem_max.
const SOCKET_RECV_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const MAX_COUNT: u32 = 1024;
const IDENTIFIER: u16 = 0;

type Nonce = [u8; PAYLOAD_NONCE_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }
}

pub struct IcmpProber {
    count: u32,
    interval: Duration,
    engines: Mutex<HashMap<Family, Result<Arc<Engine>, ProbeFault>>>,
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
            engines: Mutex::new(HashMap::new()),
        })
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Whether an ICMP socket can be opened on this host right now.
    pub fn is_runnable() -> bool {
        any_family_opens(PRE_FLIGHT_FAMILIES, |family| open_socket(family).is_ok())
    }

    fn engine_for(&self, ip: IpAddr) -> Result<Arc<Engine>, ProbeFault> {
        let family = Family::of(ip);
        get_or_open(&self.engines, family, || Engine::open(family))
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

// One openable family is enough — a pre-flight has no target, so an IPv4-only host still counts.
const PRE_FLIGHT_FAMILIES: &[Family] = &[Family::V4, Family::V6];

fn any_family_opens(families: &[Family], opens: impl Fn(Family) -> bool) -> bool {
    families.iter().copied().any(opens)
}

fn open_socket(family: Family) -> Result<Socket, ProbeFault> {
    let (domain, protocol) = match family {
        Family::V4 => (Domain::IPV4, Protocol::ICMPV4),
        Family::V6 => (Domain::IPV6, Protocol::ICMPV6),
    };

    let socket = match Socket::new(domain, Type::DGRAM, Some(protocol)) {
        Ok(s) => s,
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            // Raise cap_net_raw from permitted to effective so a `+p` non-root binary can open the raw socket.
            #[cfg(target_os = "linux")]
            crate::prober::capability::raise_net_raw_effective();
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

// An echo reply already in hand outranks a fault on a later packet: the host answered.
fn fault_when_unanswered(rtts: &[Duration], fault: Option<ProbeFault>) -> Option<ProbeFault> {
    if rtts.is_empty() {
        fault
    } else {
        None
    }
}

/// The per-waiter context the shared reader reads to validate a reply before delivering it.
#[derive(Debug, Clone, Copy)]
struct ReplyCtx {
    target: IpAddr,
    max_sequence: u16,
}

type IcmpDemux = Demux<Nonce, ReplyCtx, Duration>;

/// One shared non-blocking socket per address family plus the reader task that multiplexes every
/// probe's replies by nonce. Cached on the prober and shared for the scan.
struct Engine {
    socket: Arc<AsyncFd<Socket>>,
    demux: Arc<IcmpDemux>,
    reference: Instant,
    reader: AbortHandle,
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Engine {
    fn open(family: Family) -> Result<Arc<Engine>, ProbeFault> {
        let socket = open_socket(family)?;
        // Best-effort: the drain loop bounds the risk if the kernel rejects the size.
        let _ = socket.set_recv_buffer_size(SOCKET_RECV_BUFFER_BYTES);
        socket.set_nonblocking(true).map_err(|e| {
            ProbeFault::new(
                ProbeErrorKind::Other,
                format!("icmp: set_nonblocking failed: {e}"),
            )
        })?;
        let async_fd = AsyncFd::new(socket).map_err(|e| {
            ProbeFault::new(
                ProbeErrorKind::Other,
                format!("icmp: async fd registration failed: {e}"),
            )
        })?;
        let socket = Arc::new(async_fd);
        let demux: Arc<IcmpDemux> = Arc::new(Demux::new());
        let reference = Instant::now();
        let reader = tokio::spawn(run_reader(
            Arc::clone(&socket),
            Arc::clone(&demux),
            reference,
            family,
        ));
        Ok(Arc::new(Engine {
            socket,
            demux,
            reference,
            reader: reader.abort_handle(),
        }))
    }
}

/// Memoizes `open` per family: an open failure is cached and returned to every subsequent probe,
/// so one broken family faults uniformly instead of leaking through as absence.
fn get_or_open<T: Clone>(
    cache: &Mutex<HashMap<Family, Result<T, ProbeFault>>>,
    family: Family,
    open: impl FnOnce() -> Result<T, ProbeFault>,
) -> Result<T, ProbeFault> {
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(cached) = cache.get(&family) {
        return cached.clone();
    }
    let result = open();
    cache.insert(family, result.clone());
    result
}

/// Poisons the demux on any reader exit — a fatal `recv` (via `set_fault`) or a panic (the default
/// fault) — so a dead reader wakes every waiter with a fault instead of leaving them to time out.
struct ReaderExit {
    demux: Arc<IcmpDemux>,
    fault: ProbeFault,
}

impl ReaderExit {
    fn new(demux: Arc<IcmpDemux>) -> Self {
        Self {
            demux,
            fault: ProbeFault::new(
                ProbeErrorKind::Other,
                "icmp: reader task exited unexpectedly".to_string(),
            ),
        }
    }

    fn set_fault(&mut self, fault: ProbeFault) {
        self.fault = fault;
    }
}

impl Drop for ReaderExit {
    fn drop(&mut self) {
        self.demux.poison(self.fault.clone());
    }
}

fn recv_error_is_transient(err: &std::io::Error) -> bool {
    // EINTR interrupts the recv syscall but the socket is fine; retry instead of poisoning the family.
    err.kind() == ErrorKind::Interrupted
}

fn reader_fault(err: &std::io::Error) -> ProbeFault {
    // A dead shared reader is never absence: coerce an absence-classified io error to a fault.
    let kind = match classify::io_error(err) {
        Disposition::Fault(kind) => kind,
        Disposition::Absence => ProbeErrorKind::Other,
    };
    ProbeFault::new(kind, format!("icmp: reader recv failed: {err}"))
}

async fn run_reader(
    socket: Arc<AsyncFd<Socket>>,
    demux: Arc<IcmpDemux>,
    reference: Instant,
    family: Family,
) {
    let mut exit = ReaderExit::new(Arc::clone(&demux));
    let mut buf = [MaybeUninit::<u8>::uninit(); RECV_BUF_LEN];
    loop {
        let mut guard = match socket.readable().await {
            Ok(guard) => guard,
            Err(err) => {
                exit.set_fault(reader_fault(&err));
                return;
            }
        };
        // Drain every queued datagram per wakeup so a reply burst cannot overflow the buffer while the reader is unscheduled.
        loop {
            match guard.try_io(|sock| sock.get_ref().recv_from(&mut buf)) {
                Ok(Ok((n, from))) => {
                    let recv_at = Instant::now();
                    let bytes: &[u8] =
                        unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                    let from_ip = from.as_socket().map(|s| s.ip());
                    deliver_reply(&demux, reference, family, bytes, from_ip, recv_at);
                }
                Ok(Err(err)) if recv_error_is_transient(&err) => continue,
                Ok(Err(err)) => {
                    exit.set_fault(reader_fault(&err));
                    return;
                }
                Err(_would_block) => break,
            }
        }
    }
}

fn deliver_reply(
    demux: &IcmpDemux,
    reference: Instant,
    family: Family,
    bytes: &[u8],
    from_ip: Option<IpAddr>,
    recv_at: Instant,
) {
    let Some(nonce) = parse_reply_nonce(family, bytes) else {
        return;
    };
    let Some(ctx) = demux.context(&nonce) else {
        return;
    };
    if from_ip != Some(ctx.target) {
        return;
    }
    if let Some(sent_offset) = match_reply(ctx.target, bytes, &nonce, ctx.max_sequence) {
        let rtt = recv_at
            .saturating_duration_since(reference)
            .saturating_sub(sent_offset);
        demux.dispatch(&nonce, EngineReply::Reached(rtt));
    }
}

fn parse_reply_nonce(family: Family, bytes: &[u8]) -> Option<Nonce> {
    match family {
        Family::V4 => {
            let raw_stripped = ipv4_header_len(bytes)
                .and_then(|len| bytes.get(len..))
                .unwrap_or(&[]);
            for slice in [bytes, raw_stripped] {
                if let Some(reply) = EchoReplyPacket::new(slice) {
                    if reply.get_icmp_type() != IcmpTypes::EchoReply {
                        continue;
                    }
                    if let Some(Ok(nonce)) = reply
                        .payload()
                        .get(..PAYLOAD_NONCE_LEN)
                        .map(TryInto::try_into)
                    {
                        return Some(nonce);
                    }
                }
            }
            None
        }
        Family::V6 => {
            let reply = Icmpv6EchoReplyPacket::new(bytes)?;
            if reply.get_icmpv6_type() != Icmpv6Types::EchoReply {
                return None;
            }
            reply.payload().get(..PAYLOAD_NONCE_LEN)?.try_into().ok()
        }
    }
}

fn dest_sockaddr(target: IpAddr) -> socket2::SockAddr {
    let dest: SocketAddr = match target {
        IpAddr::V4(v4) => SocketAddr::from((v4, 0)),
        IpAddr::V6(v6) => SocketAddr::from((v6, 0)),
    };
    socket2::SockAddr::from(dest)
}

fn build_echo_request(family: Family, seq: u16, payload: &[u8]) -> [u8; ICMP_PACKET_LEN] {
    match family {
        Family::V4 => build_icmpv4_echo_request(IDENTIFIER, seq, payload),
        Family::V6 => build_icmpv6_echo_request(IDENTIFIER, seq, payload),
    }
}

fn open_fault_outcome(target_ip: IpAddr, fault: ProbeFault) -> ProbeOutcome {
    ProbeOutcome {
        lldp: None,
        gnmi_endpoint: None,
        kind: ProbeKind::Icmp,
        target_ip,
        timestamp: SystemTime::now(),
        reachable: false,
        signals: Vec::new(),
        fault: Some(fault),
    }
}

// A poison delivered mid-send outranks the send error: a dead engine is a fault, not a dark host.
fn send_failure_fault(
    mut rx: tokio::sync::oneshot::Receiver<EngineReply<Duration>>,
    send_err: Option<&std::io::Error>,
) -> Option<ProbeFault> {
    if let Ok(EngineReply::Failed(fault)) = rx.try_recv() {
        return Some(fault);
    }
    let err = send_err?;
    match classify::io_error(err) {
        Disposition::Fault(kind) => {
            Some(ProbeFault::new(kind, format!("icmp: send failed: {err}")))
        }
        Disposition::Absence => None,
    }
}

fn min_rtt_outcome(
    target_ip: IpAddr,
    rtts: &[Duration],
    fault: Option<ProbeFault>,
) -> ProbeOutcome {
    let (reachable, signals) = match rtts.iter().min().copied() {
        Some(min) => (
            true,
            vec![Signal::IcmpEchoRttMicros(min.as_micros() as u64)],
        ),
        None => (false, Vec::new()),
    };
    ProbeOutcome {
        lldp: None,
        gnmi_endpoint: None,
        kind: ProbeKind::Icmp,
        target_ip,
        timestamp: SystemTime::now(),
        reachable,
        signals,
        fault: fault_when_unanswered(rtts, fault),
    }
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
        let engine = match self.engine_for(target.ip) {
            Ok(engine) => engine,
            Err(fault) => return Ok(open_fault_outcome(target.ip, fault)),
        };

        let deadline = Instant::now() + ctx.timeout;
        let tokio_deadline = TokioInstant::from_std(deadline);
        let family = Family::of(target.ip);
        let dest = dest_sockaddr(target.ip);
        let max_sequence = self.count.saturating_sub(1).min(u16::MAX as u32) as u16;

        let mut pending: Vec<(Nonce, tokio::sync::oneshot::Receiver<EngineReply<Duration>>)> =
            Vec::with_capacity(self.count as usize);
        let mut send_fault: Option<ProbeFault> = None;

        for seq in 0..self.count {
            if Instant::now() >= deadline {
                break;
            }
            let nonce = generate_nonce();
            // Register before send so a reply that races the send has a waiter to land on.
            let rx = engine.demux.register(
                nonce,
                ReplyCtx {
                    target: target.ip,
                    max_sequence,
                },
            );
            let payload = build_payload(&nonce, engine.reference, Instant::now());
            let packet = build_echo_request(family, seq as u16, &payload);
            let send = timeout_at(
                tokio_deadline,
                engine
                    .socket
                    .async_io(Interest::WRITABLE, |sock| sock.send_to(&packet, &dest)),
            )
            .await;
            match send {
                Ok(Ok(_)) => pending.push((nonce, rx)),
                Ok(Err(err)) => {
                    engine.demux.deregister(&nonce);
                    send_fault = send_failure_fault(rx, Some(&err));
                    break;
                }
                Err(_elapsed) => {
                    engine.demux.deregister(&nonce);
                    send_fault = send_failure_fault(rx, None);
                    break;
                }
            }

            if seq + 1 < self.count && !self.interval.is_zero() {
                if Instant::now() + self.interval >= deadline {
                    break;
                }
                tokio::time::sleep(self.interval).await;
            }
        }

        let mut rtts: Vec<Duration> = Vec::with_capacity(pending.len());
        let mut poison_fault: Option<ProbeFault> = None;
        for (nonce, rx) in pending {
            match timeout_at(tokio_deadline, rx).await {
                Ok(Ok(EngineReply::Reached(rtt))) => rtts.push(rtt),
                Ok(Ok(EngineReply::Failed(fault))) => poison_fault = Some(fault),
                Ok(Err(_recv)) => {}
                Err(_elapsed) => engine.demux.deregister(&nonce),
            }
        }

        Ok(min_rtt_outcome(
            target.ip,
            &rtts,
            poison_fault.or(send_fault),
        ))
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

    fn sample_fault(detail: &str) -> ProbeFault {
        ProbeFault::new(ProbeErrorKind::Other, detail.to_string())
    }

    #[test]
    fn family_of_maps_address_to_its_socket_family() {
        assert_eq!(
            Family::of(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            Family::V4
        );
        assert_eq!(Family::of("2001:db8::1".parse().unwrap()), Family::V6);
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

    #[test]
    fn min_rtt_outcome_reports_the_minimum_over_the_echoes() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let outcome = min_rtt_outcome(
            ip,
            &[
                Duration::from_micros(3_000),
                Duration::from_micros(900),
                Duration::from_micros(2_100),
            ],
            None,
        );
        assert!(outcome.reachable);
        assert_eq!(
            outcome.signals,
            vec![Signal::IcmpEchoRttMicros(900)],
            "the signal carries the minimum rtt over the answered echoes"
        );
        assert!(outcome.fault.is_none());
    }

    #[test]
    fn min_rtt_outcome_with_no_replies_and_no_fault_is_absence() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let outcome = min_rtt_outcome(ip, &[], None);
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        assert!(
            outcome.fault.is_none(),
            "a silent host is absence, not a fault"
        );
    }

    #[test]
    fn min_rtt_outcome_with_no_replies_and_a_fault_surfaces_the_fault() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let outcome = min_rtt_outcome(ip, &[], Some(sample_fault("icmp: reader recv failed")));
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        let fault = outcome
            .fault
            .expect("a probe that learned nothing and broke surfaces the fault");
        assert!(
            fault.detail.contains("reader recv failed"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn open_fault_outcome_is_an_unreachable_kinded_fault_with_no_signals() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let outcome = open_fault_outcome(
            ip,
            ProbeFault::new(
                ProbeErrorKind::PermissionDenied,
                "icmp: raw socket unavailable",
            ),
        );
        assert_eq!(outcome.kind, ProbeKind::Icmp);
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        let fault = outcome
            .fault
            .expect("an engine-open failure is carried as a fault");
        assert_eq!(fault.kind, ProbeErrorKind::PermissionDenied);
    }

    #[test]
    fn get_or_open_caches_a_success_and_never_re_opens() {
        let cache: Mutex<HashMap<Family, Result<u32, ProbeFault>>> = Mutex::new(HashMap::new());
        let mut opens = 0;
        for _ in 0..3 {
            let value = get_or_open(&cache, Family::V4, || {
                opens += 1;
                Ok(42)
            })
            .expect("open succeeds");
            assert_eq!(value, 42);
        }
        assert_eq!(
            opens, 1,
            "a cached engine is opened exactly once for the family"
        );
    }

    #[test]
    fn get_or_open_caches_an_open_failure_and_faults_every_probe_without_re_opening() {
        let cache: Mutex<HashMap<Family, Result<u32, ProbeFault>>> = Mutex::new(HashMap::new());
        let mut opens = 0;
        for _ in 0..3 {
            let result = get_or_open(&cache, Family::V4, || {
                opens += 1;
                Err(ProbeFault::new(
                    ProbeErrorKind::PermissionDenied,
                    "no CAP_NET_RAW",
                ))
            });
            let fault = result.expect_err("a cached open failure faults the probe");
            assert_eq!(fault.kind, ProbeErrorKind::PermissionDenied);
        }
        assert_eq!(
            opens, 1,
            "a broken family caches its open fault and does not re-attempt the open per probe"
        );
    }

    #[test]
    fn get_or_open_keys_by_family_independently() {
        let cache: Mutex<HashMap<Family, Result<u32, ProbeFault>>> = Mutex::new(HashMap::new());
        let v4 = get_or_open(&cache, Family::V4, || Ok(4)).expect("v4");
        let v6 = get_or_open(&cache, Family::V6, || Ok(6)).expect("v6");
        assert_eq!((v4, v6), (4, 6));
    }

    fn craft_v4_echo_reply(
        nonce: &Nonce,
        reference: Instant,
        send_at: Instant,
        seq: u16,
    ) -> Vec<u8> {
        let payload = build_payload(nonce, reference, send_at);
        let mut packet = build_icmpv4_echo_request(IDENTIFIER, seq, &payload).to_vec();
        // Flip the type byte from EchoRequest (8) to EchoReply (0); match_reply ignores checksum.
        packet[0] = 0;
        packet
    }

    #[test]
    fn parse_reply_nonce_recovers_the_nonce_from_a_v4_echo_reply() {
        let nonce = [0x5au8; PAYLOAD_NONCE_LEN];
        let reply = craft_v4_echo_reply(&nonce, Instant::now(), Instant::now(), 0);
        assert_eq!(parse_reply_nonce(Family::V4, &reply), Some(nonce));
    }

    #[test]
    fn parse_reply_nonce_rejects_a_non_reply_packet() {
        let payload = build_payload(&[0u8; PAYLOAD_NONCE_LEN], Instant::now(), Instant::now());
        let request = build_icmpv4_echo_request(IDENTIFIER, 0, &payload);
        assert_eq!(parse_reply_nonce(Family::V4, &request), None);
    }

    #[tokio::test]
    async fn deliver_reply_hands_the_rtt_to_the_matching_waiter() {
        let demux: IcmpDemux = Demux::new();
        let target = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let nonce = [0x11u8; PAYLOAD_NONCE_LEN];
        let rx = demux.register(
            nonce,
            ReplyCtx {
                target,
                max_sequence: 0,
            },
        );

        let reference = Instant::now();
        let send_at = reference + Duration::from_micros(1_000);
        let recv_at = reference + Duration::from_micros(5_000);
        let reply = craft_v4_echo_reply(&nonce, reference, send_at, 0);

        deliver_reply(&demux, reference, Family::V4, &reply, Some(target), recv_at);

        match rx.await {
            Ok(EngineReply::Reached(rtt)) => assert_eq!(rtt, Duration::from_micros(4_000)),
            _ => panic!("the matching waiter must receive its own rtt"),
        }
    }

    #[tokio::test]
    async fn deliver_reply_drops_a_reply_from_the_wrong_source() {
        let demux: IcmpDemux = Demux::new();
        let target = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let nonce = [0x22u8; PAYLOAD_NONCE_LEN];
        let rx = demux.register(
            nonce,
            ReplyCtx {
                target,
                max_sequence: 0,
            },
        );

        let reference = Instant::now();
        let reply = craft_v4_echo_reply(&nonce, reference, reference, 0);
        let wrong_source = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

        deliver_reply(
            &demux,
            reference,
            Family::V4,
            &reply,
            Some(wrong_source),
            reference + Duration::from_micros(500),
        );

        assert_eq!(
            demux.waiter_count(),
            1,
            "a reply whose source is not the waiter's target is dropped, waiter stays pending"
        );
        drop(rx);
    }

    #[tokio::test]
    async fn deliver_reply_drops_a_reply_for_an_unregistered_nonce() {
        let demux: IcmpDemux = Demux::new();
        let target = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let reply = craft_v4_echo_reply(
            &[0x33u8; PAYLOAD_NONCE_LEN],
            Instant::now(),
            Instant::now(),
            0,
        );
        deliver_reply(
            &demux,
            Instant::now(),
            Family::V4,
            &reply,
            Some(target),
            Instant::now(),
        );
        assert_eq!(demux.waiter_count(), 0);
    }

    #[tokio::test]
    async fn a_poisoned_engine_wakes_a_waiter_with_a_fault_not_absence() {
        let demux: IcmpDemux = Demux::new();
        let rx = demux.register(
            [0x44u8; PAYLOAD_NONCE_LEN],
            ReplyCtx {
                target: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                max_sequence: 0,
            },
        );
        demux.poison(sample_fault("icmp: reader recv failed: host down"));
        match rx.await {
            Ok(EngineReply::Failed(fault)) => {
                assert!(
                    fault.detail.contains("reader recv failed"),
                    "got: {}",
                    fault.detail
                )
            }
            _ => panic!("a reader that died wakes the waiter with a fault, never a silent absence"),
        }
    }

    #[test]
    fn reader_fault_coerces_an_absence_classified_error_to_a_fault() {
        // A dead shared reader is never a dark host, even for an io kind the classifier calls absence.
        let fault = reader_fault(&std::io::Error::from(ErrorKind::ConnectionReset));
        assert_eq!(fault.kind, ProbeErrorKind::Other);
        assert!(fault.detail.contains("icmp: reader recv failed"));
    }

    #[test]
    fn reader_fault_preserves_a_permission_denied_kind() {
        let fault = reader_fault(&std::io::Error::from(ErrorKind::PermissionDenied));
        assert_eq!(fault.kind, ProbeErrorKind::PermissionDenied);
    }

    fn poisoned_waiter(detail: &str) -> tokio::sync::oneshot::Receiver<EngineReply<Duration>> {
        let demux: IcmpDemux = Demux::new();
        let rx = demux.register(
            [0x55u8; PAYLOAD_NONCE_LEN],
            ReplyCtx {
                target: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                max_sequence: 0,
            },
        );
        demux.poison(sample_fault(detail));
        rx
    }

    fn live_waiter() -> tokio::sync::oneshot::Receiver<EngineReply<Duration>> {
        let demux: IcmpDemux = Demux::new();
        demux.register(
            [0x66u8; PAYLOAD_NONCE_LEN],
            ReplyCtx {
                target: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                max_sequence: 0,
            },
        )
    }

    #[test]
    fn a_poison_delivered_during_send_outranks_an_absence_classified_send_error() {
        let rx = poisoned_waiter("icmp: reader recv failed: host down");
        let unreachable = std::io::Error::from(ErrorKind::HostUnreachable);
        let fault = send_failure_fault(rx, Some(&unreachable))
            .expect("a poison delivered mid-send outranks an absence-classified send error");
        assert!(
            fault.detail.contains("reader recv failed"),
            "the dead engine faults the probe, it is not booked as a dark host: {}",
            fault.detail
        );
    }

    #[test]
    fn a_poison_delivered_during_a_send_timeout_is_a_fault() {
        let rx = poisoned_waiter("icmp: reader recv failed: host down");
        let fault = send_failure_fault(rx, None)
            .expect("a poison delivered mid-send outranks a send timeout");
        assert!(
            fault.detail.contains("reader recv failed"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn a_send_that_fails_locally_is_a_probe_fault_not_a_silent_host() {
        let rx = live_waiter();
        let denied = std::io::Error::from(ErrorKind::PermissionDenied);
        let fault = send_failure_fault(rx, Some(&denied))
            .expect("a locally-failed send is a fault, not a silent host");
        assert_eq!(fault.kind, ProbeErrorKind::PermissionDenied);
        assert!(
            fault.detail.contains("icmp: send failed"),
            "{}",
            fault.detail
        );
    }

    #[test]
    fn a_send_that_fails_to_a_dark_host_on_a_live_engine_is_absence() {
        let rx = live_waiter();
        let unreachable = std::io::Error::from(ErrorKind::HostUnreachable);
        assert!(
            send_failure_fault(rx, Some(&unreachable)).is_none(),
            "a dark host on a live engine is absence, not a fault"
        );
    }

    #[test]
    fn a_send_timeout_on_a_live_engine_is_absence() {
        let rx = live_waiter();
        assert!(
            send_failure_fault(rx, None).is_none(),
            "a send timeout on a live engine is absence, not a fault"
        );
    }

    #[tokio::test]
    async fn dropping_reader_exit_poisons_the_demux_and_faults_the_waiter() {
        let demux: Arc<IcmpDemux> = Arc::new(Demux::new());
        let rx = demux.register(
            [0x77u8; PAYLOAD_NONCE_LEN],
            ReplyCtx {
                target: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                max_sequence: 0,
            },
        );
        let exit = ReaderExit::new(Arc::clone(&demux));
        drop(exit);
        let received = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("a dropped ReaderExit must wake the waiter, not leave it hanging");
        match received {
            Ok(EngineReply::Failed(fault)) => assert!(
                fault.detail.contains("reader task exited"),
                "got: {}",
                fault.detail
            ),
            _ => panic!("a dropped ReaderExit poisons the demux, faulting every in-flight waiter"),
        }
    }

    #[test]
    fn an_interrupted_recv_is_transient_and_other_recv_errors_are_fatal() {
        assert!(recv_error_is_transient(&std::io::Error::from(
            ErrorKind::Interrupted
        )));
        assert!(!recv_error_is_transient(&std::io::Error::from(
            ErrorKind::ConnectionReset
        )));
        assert!(!recv_error_is_transient(&std::io::Error::from(
            ErrorKind::PermissionDenied
        )));
    }

    #[tokio::test]
    async fn a_real_probe_never_contradicts_the_runnability_pre_flight() {
        use crate::model::Target;
        use std::net::Ipv4Addr;

        let prober = IcmpProber::new(1, 10).expect("valid");
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let target = ResolvedTarget {
            ip,
            original: Target::Ip(ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        };
        let outcome = prober
            .probe(&target, &ProbeCtx::new(Duration::from_millis(500), 0))
            .await
            .expect("probe ok");
        let denied = outcome
            .fault
            .as_ref()
            .is_some_and(|fault| fault.kind == ProbeErrorKind::PermissionDenied);
        if IcmpProber::is_runnable() {
            assert!(
                !denied,
                "an openable socket must not produce PermissionDenied"
            );
        } else {
            assert!(
                outcome.fault.is_some(),
                "an unopenable socket must fault, never look like absence"
            );
        }
    }

    #[test]
    fn one_openable_family_is_enough() {
        assert!(any_family_opens(PRE_FLIGHT_FAMILIES, |family| family == Family::V4));
        assert!(any_family_opens(PRE_FLIGHT_FAMILIES, |family| family == Family::V6));
        assert!(!any_family_opens(PRE_FLIGHT_FAMILIES, |_| false));
    }

    #[test]
    fn is_runnable_asks_a_real_socket_open_of_each_family() {
        let per_family = PRE_FLIGHT_FAMILIES
            .iter()
            .map(|family| open_socket(*family).is_ok());
        assert_eq!(
            IcmpProber::is_runnable(),
            per_family.into_iter().any(|opened| opened)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn is_runnable_is_true_on_macos_for_any_user() {
        assert!(
            IcmpProber::is_runnable(),
            "macOS grants unprivileged SOCK_DGRAM ICMP"
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
        let ctx = ProbeCtx::new(Duration::from_secs(2), 0);
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
