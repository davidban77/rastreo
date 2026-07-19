use std::collections::HashMap;
use std::fmt::{self, Display};
use std::hash::Hash;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use pnet_datalink::{Channel, Config, DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface};
use tokio::time::{timeout_at, Instant as TokioInstant};

use crate::error::{ProbeErrorKind, RastreoError};
use crate::model::{ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::classify::{self, Disposition};
use crate::prober::demux::{Demux, EngineReply};

pub(crate) const ETH_HEADER_LEN: usize = 14;
const RECV_POLL_INTERVAL: Duration = Duration::from_millis(50);
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// Generous so a wide scan's reply burst queues in the kernel AF_PACKET receive buffer instead of
/// overflowing while the reader thread drains it; the kernel clamps to rmem_max without CAP_NET_ADMIN.
#[cfg(target_os = "linux")]
const SOCKET_RECV_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// The BPF store buffer is the macOS drop point; pnet copies it straight to `BIOCSBLEN`.
#[cfg(not(target_os = "linux"))]
const BPF_READ_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// The per-protocol seam — address family, packet build/parse, interface/source selection — that the
/// shared engine drives.
pub(crate) trait LinkLayerProtocol: Send + Sync + 'static {
    type Addr: Copy + Eq + Hash + Display + Send + 'static;

    const NAME: &'static str;
    const NAME_UPPER: &'static str;
    const ADDRESS_FAMILY: &'static str;

    fn kind() -> ProbeKind;
    fn extract_target(ip: IpAddr) -> Option<Self::Addr>;
    fn wrong_family_detail() -> &'static str;
    fn select_interface(target: Self::Addr) -> Option<NetworkInterface>;
    fn source_address(iface: &NetworkInterface, target: Self::Addr) -> Option<Self::Addr>;
    fn build_request(src_mac: MacAddr, src_ip: Self::Addr, target: Self::Addr) -> Vec<u8>;

    /// Which address a reply announces, and its MAC. The shared reader has no target in hand, so it
    /// keys the reply by its announced address. Every per-frame validity filter (ethertype, opcode,
    /// option type) stays; only the `== target` equality check is dropped.
    fn parse_reply_source(frame: &[u8]) -> Option<(Self::Addr, MacAddr)>;
}

pub(crate) fn lookup_interface(name: &str) -> Option<NetworkInterface> {
    pnet_datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
}

pub(crate) fn format_mac(mac: MacAddr) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac.0, mac.1, mac.2, mac.3, mac.4, mac.5
    )
}

type LinkLayerDemux<P> = Demux<<P as LinkLayerProtocol>::Addr, (), MacAddr>;
type EngineCache<P> = Mutex<HashMap<String, Result<Arc<Engine<P>>, ProbeFault>>>;

/// One shared datalink channel per (protocol, interface) plus the reader thread that multiplexes
/// every probe's reply by the reply's announced address. Cached on the prober and shared for the scan.
struct Engine<P: LinkLayerProtocol> {
    demux: Arc<LinkLayerDemux<P>>,
    sender: Arc<Mutex<Box<dyn DataLinkSender>>>,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
}

impl<P: LinkLayerProtocol> Drop for Engine<P> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl<P: LinkLayerProtocol> Engine<P> {
    fn open(iface: &NetworkInterface) -> Result<Arc<Engine<P>>, ProbeFault> {
        let (tx, rx) = match open_datalink_channel(iface) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(ProbeFault::new(
                    ProbeErrorKind::Other,
                    format!("{} channel returned an unsupported backend", P::NAME),
                ))
            }
            Err(err) => return Err(channel_open_fault::<P>(&err)),
        };

        let demux: Arc<LinkLayerDemux<P>> = Arc::new(Demux::new());
        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let demux = Arc::clone(&demux);
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name(format!("rastreo-{}-reader", P::NAME))
                .spawn(move || run_reader::<P>(rx, demux, stop))
                .map_err(|e| {
                    ProbeFault::new(
                        ProbeErrorKind::Other,
                        format!("{} reader thread spawn failed: {e}", P::NAME),
                    )
                })?
        };

        Ok(Arc::new(Engine {
            demux,
            sender: Arc::new(Mutex::new(tx)),
            stop,
            reader: Some(reader),
        }))
    }
}

/// Poisons the demux if the reader exits by a fatal recv or a panic, but is disarmed on a clean
/// stop-flag exit so a normal engine teardown wakes no waiter with a spurious fault.
struct ReaderExit<P: LinkLayerProtocol> {
    demux: Arc<LinkLayerDemux<P>>,
    fault: Option<ProbeFault>,
}

impl<P: LinkLayerProtocol> ReaderExit<P> {
    fn new(demux: Arc<LinkLayerDemux<P>>) -> Self {
        Self {
            demux,
            fault: Some(ProbeFault::new(
                ProbeErrorKind::Other,
                format!("{} reader thread exited unexpectedly", P::NAME),
            )),
        }
    }

    fn set_fault(&mut self, fault: ProbeFault) {
        self.fault = Some(fault);
    }

    fn disarm(&mut self) {
        self.fault = None;
    }
}

impl<P: LinkLayerProtocol> Drop for ReaderExit<P> {
    fn drop(&mut self) {
        if let Some(fault) = self.fault.take() {
            self.demux.poison(fault);
        }
    }
}

fn recv_error_is_transient(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
    )
}

fn reader_fault<P: LinkLayerProtocol>(err: &std::io::Error) -> ProbeFault {
    // A dead shared reader is never absence: coerce an absence-classified io error to a fault.
    let kind = match classify::io_error(err) {
        Disposition::Fault(kind) => kind,
        Disposition::Absence => ProbeErrorKind::Other,
    };
    ProbeFault::new(kind, format!("{} reader recv failed: {err}", P::NAME))
}

fn run_reader<P: LinkLayerProtocol>(
    mut rx: Box<dyn DataLinkReceiver>,
    demux: Arc<LinkLayerDemux<P>>,
    stop: Arc<AtomicBool>,
) {
    let mut exit = ReaderExit::<P>::new(Arc::clone(&demux));
    while !stop.load(Ordering::Relaxed) {
        match rx.next() {
            Ok(frame) => {
                if let Some((addr, mac)) = P::parse_reply_source(frame) {
                    demux.dispatch(&addr, EngineReply::Reached(mac));
                }
            }
            Err(err) if recv_error_is_transient(&err) => continue,
            Err(err) => {
                exit.set_fault(reader_fault::<P>(&err));
                return;
            }
        }
    }
    exit.disarm();
}

#[cfg(target_os = "linux")]
fn open_datalink_channel(iface: &NetworkInterface) -> std::io::Result<Channel> {
    let fd = open_af_packet_socket()?;
    pnet_datalink::channel(iface, linux_channel_config(fd))
}

#[cfg(not(target_os = "linux"))]
fn open_datalink_channel(iface: &NetworkInterface) -> std::io::Result<Channel> {
    pnet_datalink::channel(iface, bpf_channel_config())
}

#[cfg(target_os = "linux")]
fn open_af_packet_socket() -> std::io::Result<std::os::fd::RawFd> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::os::fd::IntoRawFd;

    // Raise cap_net_raw from permitted to effective so a `+p` non-root binary can open the socket.
    crate::prober::capability::raise_net_raw_effective();

    // The protocol arg is irrelevant here — pnet re-binds the fd with its own sll_protocol before capture.
    const ETH_P_ALL: i32 = 0x0003;
    let socket = Socket::new(
        Domain::PACKET,
        Type::RAW,
        Some(Protocol::from(ETH_P_ALL.to_be())),
    )?;
    // Best-effort: the kernel clamps to rmem_max without CAP_NET_ADMIN; pnet never resets it.
    let _ = socket.set_recv_buffer_size(SOCKET_RECV_BUFFER_BYTES);
    Ok(socket.into_raw_fd())
}

#[cfg(target_os = "linux")]
fn linux_channel_config(fd: std::os::fd::RawFd) -> Config {
    Config {
        read_timeout: Some(RECV_POLL_INTERVAL),
        write_timeout: Some(WRITE_TIMEOUT),
        promiscuous: false,
        socket_fd: Some(fd),
        ..Default::default()
    }
}

#[cfg(not(target_os = "linux"))]
fn bpf_channel_config() -> Config {
    Config {
        read_timeout: Some(RECV_POLL_INTERVAL),
        write_timeout: Some(WRITE_TIMEOUT),
        read_buffer_size: BPF_READ_BUFFER_BYTES,
        promiscuous: false,
        ..Default::default()
    }
}

fn channel_open_fault<P: LinkLayerProtocol>(err: &std::io::Error) -> ProbeFault {
    if err.kind() == ErrorKind::PermissionDenied {
        ProbeFault::new(
            ProbeErrorKind::PermissionDenied,
            format!(
                "raw socket permission denied; {} requires CAP_NET_RAW",
                P::NAME_UPPER
            ),
        )
    } else {
        ProbeFault::new(
            ProbeErrorKind::Other,
            format!("{} channel open failed: {err}", P::NAME),
        )
    }
}

/// Memoizes an engine open per interface: an open failure is cached and returned to every subsequent
/// probe for that interface, so one broken interface faults uniformly instead of leaking as absence.
fn get_or_open<T: Clone>(
    cache: &Mutex<HashMap<String, Result<T, ProbeFault>>>,
    key: &str,
    open: impl FnOnce() -> Result<T, ProbeFault>,
) -> Result<T, ProbeFault> {
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(cached) = cache.get(key) {
        return cached.clone();
    }
    let result = open();
    cache.insert(key.to_string(), result.clone());
    result
}

/// The per-protocol engine cache the prober holds for the scan.
pub(crate) struct LinkLayerEngines<P: LinkLayerProtocol> {
    engines: EngineCache<P>,
}

impl<P: LinkLayerProtocol> Default for LinkLayerEngines<P> {
    fn default() -> Self {
        Self {
            engines: Mutex::new(HashMap::new()),
        }
    }
}

impl<P: LinkLayerProtocol> LinkLayerEngines<P> {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn engine_for(&self, iface: &NetworkInterface) -> Result<Arc<Engine<P>>, ProbeFault> {
        get_or_open(&self.engines, &iface.name, || Engine::<P>::open(iface))
    }
}

impl<P: LinkLayerProtocol> fmt::Debug for LinkLayerEngines<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkLayerEngines").finish_non_exhaustive()
    }
}

fn fault_outcome<P: LinkLayerProtocol>(target_ip: IpAddr, fault: ProbeFault) -> ProbeOutcome {
    ProbeOutcome {
        kind: P::kind(),
        target_ip,
        timestamp: SystemTime::now(),
        reachable: false,
        signals: Vec::new(),
        fault: Some(fault),
    }
}

// A local resolution failure (privileged socket denied, no usable interface) is a broken probe,
// carried as a fault on an unreachable outcome — never discarded.
fn link_layer_fault<P: LinkLayerProtocol>(target_ip: IpAddr, detail: String) -> ProbeOutcome {
    fault_outcome::<P>(target_ip, ProbeFault::new(ProbeErrorKind::Other, detail))
}

fn reached_outcome<P: LinkLayerProtocol>(target_ip: IpAddr, mac: MacAddr) -> ProbeOutcome {
    ProbeOutcome {
        kind: P::kind(),
        target_ip,
        timestamp: SystemTime::now(),
        reachable: true,
        signals: vec![Signal::Mac(format_mac(mac))],
        fault: None,
    }
}

// A silent host is a negative discovery result, not a probe fault.
fn absence_outcome<P: LinkLayerProtocol>(target_ip: IpAddr) -> ProbeOutcome {
    ProbeOutcome {
        kind: P::kind(),
        target_ip,
        timestamp: SystemTime::now(),
        reachable: false,
        signals: Vec::new(),
        fault: None,
    }
}

fn reply_to_outcome<P: LinkLayerProtocol>(
    target_ip: IpAddr,
    reply: Option<EngineReply<MacAddr>>,
) -> ProbeOutcome {
    match reply {
        Some(EngineReply::Reached(mac)) => reached_outcome::<P>(target_ip, mac),
        Some(EngineReply::Failed(fault)) => fault_outcome::<P>(target_ip, fault),
        None => absence_outcome::<P>(target_ip),
    }
}

pub(crate) async fn probe_link_layer<P: LinkLayerProtocol>(
    engines: &LinkLayerEngines<P>,
    interface: &str,
    target: &ResolvedTarget,
    ctx: &ProbeCtx,
) -> Result<ProbeOutcome, RastreoError> {
    let target_addr = match P::extract_target(target.ip) {
        Some(addr) => addr,
        None => {
            return Ok(link_layer_fault::<P>(
                target.ip,
                P::wrong_family_detail().to_string(),
            ))
        }
    };

    let iface = if interface.is_empty() {
        match P::select_interface(target_addr) {
            Some(iface) => iface,
            None => {
                return Ok(link_layer_fault::<P>(
                    target.ip,
                    format!("no local interface reaches {target_addr}"),
                ))
            }
        }
    } else {
        match lookup_interface(interface) {
            Some(iface) => iface,
            None => {
                return Ok(link_layer_fault::<P>(
                    target.ip,
                    format!("network interface '{interface}' not found"),
                ))
            }
        }
    };

    let Some(src_mac) = iface.mac else {
        return Ok(link_layer_fault::<P>(
            target.ip,
            format!("interface {} has no MAC address", iface.name),
        ));
    };
    let Some(src_ip) = P::source_address(&iface, target_addr) else {
        return Ok(link_layer_fault::<P>(
            target.ip,
            format!(
                "interface {} has no {} address",
                iface.name,
                P::ADDRESS_FAMILY
            ),
        ));
    };
    if src_ip == target_addr {
        return Ok(link_layer_fault::<P>(
            target.ip,
            format!(
                "{} target {target_addr} is a local interface address",
                P::NAME
            ),
        ));
    }

    let engine = match engines.engine_for(&iface) {
        Ok(engine) => engine,
        Err(fault) => return Ok(fault_outcome::<P>(target.ip, fault)),
    };

    // Register before send so a reply that races the send has a waiter to land on. The key is the
    // target address for the whole deadline — one registration per probe, so a future retransmit
    // re-sends without re-registering and cannot trip the demux collision guard.
    let rx = engine.demux.register(target_addr, ());

    let frame = P::build_request(src_mac, src_ip, target_addr);
    // Drop the sender lock before the await: the await blocks on the receiver, not the tx.
    let send_result = {
        let mut sender = engine
            .sender
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        sender.send_to(&frame, None)
    };
    match send_result {
        Some(Ok(())) => {}
        // A jammed raw tx is a broken engine, not target absence.
        Some(Err(err)) => {
            engine.demux.deregister(&target_addr);
            return Ok(link_layer_fault::<P>(
                target.ip,
                format!("{} send failed: {err}", P::NAME),
            ));
        }
        None => {
            engine.demux.deregister(&target_addr);
            return Ok(link_layer_fault::<P>(
                target.ip,
                format!(
                    "{} send returned None (packet too large for send buffer)",
                    P::NAME
                ),
            ));
        }
    }

    let deadline = TokioInstant::now() + ctx.timeout;
    let reply = match timeout_at(deadline, rx).await {
        Ok(Ok(engine_reply)) => Some(engine_reply),
        Ok(Err(_recv)) => None,
        Err(_elapsed) => {
            engine.demux.deregister(&target_addr);
            None
        }
    };
    Ok(reply_to_outcome::<P>(target.ip, reply))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    struct TestProtocol;

    impl LinkLayerProtocol for TestProtocol {
        type Addr = Ipv4Addr;

        const NAME: &'static str = "test";
        const NAME_UPPER: &'static str = "TEST";
        const ADDRESS_FAMILY: &'static str = "ipv4";

        fn kind() -> ProbeKind {
            ProbeKind::Arp
        }

        fn extract_target(ip: IpAddr) -> Option<Ipv4Addr> {
            match ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            }
        }

        fn wrong_family_detail() -> &'static str {
            "test protocol requires an ipv4 target"
        }

        fn select_interface(_target: Ipv4Addr) -> Option<NetworkInterface> {
            None
        }

        fn source_address(_iface: &NetworkInterface, _target: Ipv4Addr) -> Option<Ipv4Addr> {
            None
        }

        fn build_request(_src_mac: MacAddr, _src_ip: Ipv4Addr, _target: Ipv4Addr) -> Vec<u8> {
            Vec::new()
        }

        fn parse_reply_source(_frame: &[u8]) -> Option<(Ipv4Addr, MacAddr)> {
            None
        }
    }

    fn sample_fault(detail: &str) -> ProbeFault {
        ProbeFault::new(ProbeErrorKind::Other, detail.to_string())
    }

    #[test]
    fn format_mac_is_lower_hex_colon_separated() {
        let mac = MacAddr::new(0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc);
        assert_eq!(format_mac(mac), "00:11:22:aa:bb:cc");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_channel_config_splits_the_buffer_knob_onto_the_socket_fd() {
        let config = linux_channel_config(7);
        assert!(!config.promiscuous, "must not enter promiscuous mode");
        assert_eq!(config.read_timeout, Some(RECV_POLL_INTERVAL));
        assert_eq!(config.write_timeout, Some(WRITE_TIMEOUT));
        assert_eq!(
            config.socket_fd,
            Some(7),
            "linux hands its own SO_RCVBUF-sized socket to pnet"
        );
        assert!(config.linux_fanout.is_none());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn bpf_channel_config_sizes_the_read_buffer_and_takes_no_socket_fd() {
        let config = bpf_channel_config();
        assert!(!config.promiscuous, "must not enter promiscuous mode");
        assert_eq!(config.read_timeout, Some(RECV_POLL_INTERVAL));
        assert_eq!(config.write_timeout, Some(WRITE_TIMEOUT));
        assert_eq!(config.read_buffer_size, BPF_READ_BUFFER_BYTES);
        assert!(
            config.socket_fd.is_none(),
            "the bpf backend opens /dev/bpf* itself"
        );
    }

    #[test]
    fn reply_to_outcome_maps_a_timeout_to_absence() {
        let target_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42));
        let outcome = reply_to_outcome::<TestProtocol>(target_ip, None);
        assert_eq!(outcome.kind, TestProtocol::kind());
        assert_eq!(outcome.target_ip, target_ip);
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        assert!(
            outcome.fault.is_none(),
            "a silent host is absence, not a fault"
        );
    }

    #[test]
    fn reply_to_outcome_maps_a_reached_reply_to_a_reachable_mac_signal() {
        let target_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42));
        let mac = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
        let outcome = reply_to_outcome::<TestProtocol>(target_ip, Some(EngineReply::Reached(mac)));
        assert!(outcome.reachable);
        assert!(matches!(&outcome.signals[0], Signal::Mac(m) if m == "aa:bb:cc:dd:ee:ff"));
        assert!(outcome.fault.is_none());
    }

    #[test]
    fn reply_to_outcome_maps_a_failed_delivery_to_a_kinded_fault() {
        let target_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42));
        let outcome = reply_to_outcome::<TestProtocol>(
            target_ip,
            Some(EngineReply::Failed(sample_fault(
                "raw socket permission denied",
            ))),
        );
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        let fault = outcome
            .fault
            .expect("a probe fault is recorded on the outcome");
        assert_eq!(fault.kind, ProbeErrorKind::Other);
        assert!(
            fault.detail.contains("permission denied"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn channel_open_fault_names_cap_net_raw_on_permission_denied() {
        let fault =
            channel_open_fault::<TestProtocol>(&std::io::Error::from(ErrorKind::PermissionDenied));
        assert_eq!(fault.kind, ProbeErrorKind::PermissionDenied);
        assert!(
            fault.detail.contains("CAP_NET_RAW"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn a_permission_denied_channel_open_surfaces_the_cap_net_raw_hint() {
        let fault =
            channel_open_fault::<TestProtocol>(&std::io::Error::from(ErrorKind::PermissionDenied));
        assert_eq!(fault.kind, ProbeErrorKind::PermissionDenied);
        let hint = crate::hints::hint_for_error_kind(fault.kind).expect("permission-denied hint");
        assert!(hint.contains("CAP_NET_RAW"), "hint: {hint}");
    }

    #[test]
    fn channel_open_fault_reports_other_open_errors_verbatim() {
        let fault = channel_open_fault::<TestProtocol>(&std::io::Error::from(ErrorKind::NotFound));
        assert!(
            fault.detail.contains("channel open failed"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn reader_fault_coerces_an_absence_classified_error_to_a_fault() {
        let fault = reader_fault::<TestProtocol>(&std::io::Error::from(ErrorKind::ConnectionReset));
        assert_eq!(fault.kind, ProbeErrorKind::Other);
        assert!(fault.detail.contains("reader recv failed"));
    }

    #[test]
    fn an_interrupted_or_timed_out_recv_is_transient_and_other_recv_errors_are_fatal() {
        assert!(recv_error_is_transient(&std::io::Error::from(
            ErrorKind::TimedOut
        )));
        assert!(recv_error_is_transient(&std::io::Error::from(
            ErrorKind::WouldBlock
        )));
        assert!(recv_error_is_transient(&std::io::Error::from(
            ErrorKind::Interrupted
        )));
        assert!(!recv_error_is_transient(&std::io::Error::from(
            ErrorKind::ConnectionReset
        )));
    }

    #[test]
    fn get_or_open_caches_a_success_and_never_re_opens() {
        let cache: Mutex<HashMap<String, Result<u32, ProbeFault>>> = Mutex::new(HashMap::new());
        let mut opens = 0;
        for _ in 0..3 {
            let value = get_or_open(&cache, "eth0", || {
                opens += 1;
                Ok(42)
            })
            .expect("open succeeds");
            assert_eq!(value, 42);
        }
        assert_eq!(
            opens, 1,
            "a cached engine is opened exactly once per interface"
        );
    }

    #[test]
    fn get_or_open_caches_an_open_failure_and_faults_every_probe_without_re_opening() {
        let cache: Mutex<HashMap<String, Result<u32, ProbeFault>>> = Mutex::new(HashMap::new());
        let mut opens = 0;
        for _ in 0..3 {
            let result = get_or_open(&cache, "eth0", || {
                opens += 1;
                Err(ProbeFault::new(
                    ProbeErrorKind::Other,
                    "raw socket permission denied; ARP requires CAP_NET_RAW",
                ))
            });
            let fault = result.expect_err("a cached open failure faults the probe");
            assert!(
                fault.detail.contains("CAP_NET_RAW"),
                "got: {}",
                fault.detail
            );
        }
        assert_eq!(
            opens, 1,
            "a broken interface caches its open fault and does not re-attempt the open per probe"
        );
    }

    #[test]
    fn get_or_open_keys_by_interface_independently() {
        let cache: Mutex<HashMap<String, Result<u32, ProbeFault>>> = Mutex::new(HashMap::new());
        let a = get_or_open(&cache, "eth0", || Ok(1)).expect("eth0");
        let b = get_or_open(&cache, "eth1", || Ok(2)).expect("eth1");
        assert_eq!((a, b), (1, 2));
    }

    #[tokio::test]
    async fn dropping_reader_exit_poisons_the_demux_and_faults_the_waiter() {
        let demux: Arc<LinkLayerDemux<TestProtocol>> = Arc::new(Demux::new());
        let rx = demux.register(Ipv4Addr::new(10, 0, 0, 1), ());
        let exit = ReaderExit::<TestProtocol>::new(Arc::clone(&demux));
        drop(exit);
        let received = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("a dropped ReaderExit must wake the waiter, not leave it hanging");
        match received {
            Ok(EngineReply::Failed(fault)) => assert!(
                fault.detail.contains("reader thread exited"),
                "got: {}",
                fault.detail
            ),
            _ => panic!("a dropped ReaderExit poisons the demux, faulting every in-flight waiter"),
        }
    }

    #[tokio::test]
    async fn a_disarmed_reader_exit_does_not_poison_on_a_clean_stop() {
        let demux: Arc<LinkLayerDemux<TestProtocol>> = Arc::new(Demux::new());
        let rx = demux.register(Ipv4Addr::new(10, 0, 0, 1), ());
        let mut exit = ReaderExit::<TestProtocol>::new(Arc::clone(&demux));
        exit.disarm();
        drop(exit);
        // A clean stop leaves the waiter pending (it will time out as absence), never faults it.
        assert_eq!(demux.waiter_count(), 1);
        drop(rx);
    }

    #[tokio::test]
    async fn a_set_reader_fault_poisons_the_waiter_with_that_fault() {
        let demux: Arc<LinkLayerDemux<TestProtocol>> = Arc::new(Demux::new());
        let rx = demux.register(Ipv4Addr::new(10, 0, 0, 1), ());
        let mut exit = ReaderExit::<TestProtocol>::new(Arc::clone(&demux));
        exit.set_fault(reader_fault::<TestProtocol>(&std::io::Error::from(
            ErrorKind::ConnectionReset,
        )));
        drop(exit);
        match rx.await {
            Ok(EngineReply::Failed(fault)) => assert!(
                fault.detail.contains("reader recv failed"),
                "got: {}",
                fault.detail
            ),
            _ => panic!("a fatal recv poisons in-flight waiters with the recv fault"),
        }
    }
}
