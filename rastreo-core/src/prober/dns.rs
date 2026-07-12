use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolveHosts, ResolverConfig,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;

use crate::error::{ConfigError, ProbeError, RastreoError};
use crate::model::{ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::classify::{self, Disposition};
use crate::prober::Prober;

const MAX_LABEL_BYTES: usize = 63;
const MAX_NAME_BYTES: usize = 253;

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DnsQueryType {
    #[default]
    A,
    Aaaa,
    Mx,
    Txt,
    Ptr,
    Ns,
    Cname,
}

impl DnsQueryType {
    fn to_record_type(self) -> RecordType {
        match self {
            Self::A => RecordType::A,
            Self::Aaaa => RecordType::AAAA,
            Self::Mx => RecordType::MX,
            Self::Txt => RecordType::TXT,
            Self::Ptr => RecordType::PTR,
            Self::Ns => RecordType::NS,
            Self::Cname => RecordType::CNAME,
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DnsTransport {
    #[default]
    Udp,
    Tcp,
}

impl DnsTransport {
    fn protocol_config(self) -> ProtocolConfig {
        match self {
            Self::Udp => ProtocolConfig::Udp,
            Self::Tcp => ProtocolConfig::Tcp,
        }
    }
}

#[derive(Debug)]
pub struct DnsProber {
    ports: Vec<u16>,
    query_names: Arc<[String]>,
    query_type: DnsQueryType,
    transport: DnsTransport,
    recursion_desired: bool,
}

impl DnsProber {
    pub fn new(
        ports: Vec<u16>,
        query_names: Vec<String>,
        query_type: DnsQueryType,
        transport: DnsTransport,
        recursion_desired: bool,
    ) -> Result<Self, RastreoError> {
        if ports.is_empty() {
            return Err(ConfigError::invalid("dns prober requires at least one port").into());
        }
        if query_names.is_empty() {
            return Err(ConfigError::invalid("dns prober requires at least one query_name").into());
        }
        for name in &query_names {
            validate_dns_name(name)?;
        }

        let mut ports = ports;
        ports.sort_unstable();
        ports.dedup();

        Ok(Self {
            ports,
            query_names: query_names.into(),
            query_type,
            transport,
            recursion_desired,
        })
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    pub fn query_names(&self) -> &[String] {
        &self.query_names
    }

    pub fn query_type(&self) -> DnsQueryType {
        self.query_type
    }

    pub fn transport(&self) -> DnsTransport {
        self.transport
    }

    pub fn recursion_desired(&self) -> bool {
        self.recursion_desired
    }

    fn build_resolver(&self, target_ip: IpAddr, port: u16) -> Result<TokioResolver, NetError> {
        let mut connection = ConnectionConfig::new(self.transport.protocol_config());
        connection.port = port;
        let name_server = NameServerConfig::new(target_ip, true, vec![connection]);
        let config = ResolverConfig::from_parts(None, Vec::new(), vec![name_server]);
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        let opts = builder.options_mut();
        opts.attempts = 1;
        opts.recursion_desired = self.recursion_desired;
        opts.cache_size = 0;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.num_concurrent_reqs = 1;
        opts.try_tcp_on_error = false;
        // Outer tokio::time::timeout owns the deadline; keep the inner timeout wide.
        opts.timeout = Duration::from_secs(3600);
        builder.build()
    }
}

/// Serde default for `ProberConfig::Dns.ports` — `[53]`.
pub fn default_ports() -> Vec<u16> {
    vec![53]
}

/// Serde default for `ProberConfig::Dns.recursion_desired` — `true`.
///
/// Most caching resolvers set the RD bit by default; scenarios probing authoritative-only
/// servers should override to `false` to avoid triggering unwanted recursion.
pub fn default_recursion_desired() -> bool {
    true
}

fn validate_dns_name(name: &str) -> Result<(), RastreoError> {
    if name.is_empty() {
        return Err(ConfigError::invalid("dns prober query_name must not be empty").into());
    }
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        return Err(ConfigError::invalid("dns prober query_name must not be empty").into());
    }
    if trimmed.len() > MAX_NAME_BYTES {
        return Err(ConfigError::invalid(format!(
            "dns prober query_name {name:?} exceeds {MAX_NAME_BYTES} bytes"
        ))
        .into());
    }
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(ConfigError::invalid(format!(
                "dns prober query_name {name:?} contains an empty label"
            ))
            .into());
        }
        if label.len() > MAX_LABEL_BYTES {
            return Err(ConfigError::invalid(format!(
                "dns prober query_name {name:?} has a label longer than {MAX_LABEL_BYTES} bytes"
            ))
            .into());
        }
    }
    Ok(())
}

fn format_signal(query_name: &str, rdata: &RData) -> Option<String> {
    match rdata {
        RData::A(a) => Some(format!("{query_name} -> {}", a.0)),
        RData::AAAA(aaaa) => Some(format!("{query_name} -> {}", aaaa.0)),
        RData::MX(mx) => Some(format!("{query_name} -> {} {}", mx.preference, mx.exchange)),
        RData::TXT(txt) => {
            let joined = txt
                .txt_data
                .iter()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .collect::<Vec<_>>()
                .join("");
            Some(format!("{query_name} -> \"{joined}\""))
        }
        RData::PTR(ptr) => Some(format!("{query_name} -> {}", ptr.0)),
        RData::NS(ns) => Some(format!("{query_name} -> {}", ns.0)),
        RData::CNAME(cname) => Some(format!("{query_name} -> {}", cname.0)),
        _ => None,
    }
}

#[async_trait::async_trait]
impl Prober for DnsProber {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Dns
    }

    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError> {
        let record_type = self.query_type.to_record_type();
        let mut signals = Vec::new();
        let mut any_reachable = false;
        let mut last_fault: Option<String> = None;

        for &port in &self.ports {
            let resolver = match self.build_resolver(target.ip, port) {
                Ok(r) => r,
                Err(e) => {
                    last_fault = Some(format!("failed to build dns resolver on port {port}: {e}"));
                    continue;
                }
            };
            for name in self.query_names.iter() {
                let lookup = resolver.lookup(name.as_str(), record_type);
                match tokio::time::timeout(ctx.timeout, lookup).await {
                    Ok(Ok(response)) => {
                        any_reachable = true;
                        for record in response.answers() {
                            if let Some(text) = format_signal(name, &record.data) {
                                signals.push(Signal::DnsHost(text));
                            }
                        }
                    }
                    Ok(Err(err)) => {
                        if err.is_no_records_found() {
                            // NXDOMAIN, NoError-with-empty-answers: server responded.
                            any_reachable = true;
                            continue;
                        }
                        if let hickory_resolver::net::NetError::Dns(
                            hickory_resolver::net::DnsError::ResponseCode(_),
                        ) = &err
                        {
                            // REFUSED / SERVFAIL / etc. — server responded.
                            any_reachable = true;
                            continue;
                        }
                        if classify::net_error(&err) == Disposition::Fault {
                            last_fault =
                                Some(format!("dns probe failed on port {port} for {name}: {err}"));
                        }
                    }
                    Err(_) => {}
                }
            }
        }

        if !any_reachable {
            // Silence on one port is not evidence against a fault on another, but an answer is.
            if let Some(msg) = last_fault {
                return Err(ProbeError::Other(msg).into());
            }
            return Ok(ProbeOutcome {
                kind: ProbeKind::Dns,
                target_ip: target.ip,
                timestamp: SystemTime::now(),
                reachable: false,
                signals: Vec::new(),
            });
        }

        Ok(ProbeOutcome {
            kind: ProbeKind::Dns,
            target_ip: target.ip,
            timestamp: SystemTime::now(),
            reachable: any_reachable,
            signals,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_resolver::proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, TXT};
    use hickory_resolver::proto::rr::{Name, RData, Record};
    use hickory_resolver::proto::serialize::binary::{BinDecodable, BinEncodable};
    use tokio::net::{TcpListener, UdpSocket};

    use crate::model::Target;

    fn loopback_target() -> ResolvedTarget {
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        ResolvedTarget {
            ip: addr,
            original: Target::Ip(addr),
            resolved_at: SystemTime::UNIX_EPOCH,
        }
    }

    fn ctx_with_timeout(ms: u64) -> ProbeCtx {
        ProbeCtx {
            timeout: Duration::from_millis(ms),
            retries: 0,
        }
    }

    fn build_response(query: &Query, answers: Vec<Record>, response_code: ResponseCode) -> Message {
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.metadata.response_code = response_code;
        message.metadata.recursion_available = true;
        message.metadata.recursion_desired = true;
        message.add_query(query.clone());
        message.add_answers(answers);
        message
    }

    type ResponderFn = dyn Fn(&Query) -> (Vec<Record>, ResponseCode) + Send + Sync;

    #[derive(Clone)]
    struct DnsResponder(Arc<ResponderFn>);

    async fn spawn_udp_dns_server(bind: &str, responder: DnsResponder) -> std::io::Result<u16> {
        let socket = UdpSocket::bind(bind).await?;
        let port = socket.local_addr()?.port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let request = match Message::from_bytes(&buf[..n]) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let query = match request.queries.first() {
                    Some(q) => q.clone(),
                    None => continue,
                };
                let (answers, rcode) = (responder.0)(&query);
                let mut response = build_response(&query, answers, rcode);
                response.metadata.id = request.metadata.id;
                let bytes = match response.to_bytes() {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let _ = socket.send_to(&bytes, peer).await;
            }
        });
        Ok(port)
    }

    async fn spawn_tcp_dns_server(bind: &str, responder: DnsResponder) -> std::io::Result<u16> {
        let listener = TcpListener::bind(bind).await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let responder = responder.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut buf = vec![0u8; len];
                    if stream.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    let request = match Message::from_bytes(&buf) {
                        Ok(m) => m,
                        Err(_) => return,
                    };
                    let query = match request.queries.first() {
                        Some(q) => q.clone(),
                        None => return,
                    };
                    let (answers, rcode) = (responder.0)(&query);
                    let mut response = build_response(&query, answers, rcode);
                    response.metadata.id = request.metadata.id;
                    let bytes = match response.to_bytes() {
                        Ok(b) => b,
                        Err(_) => return,
                    };
                    let out_len = (bytes.len() as u16).to_be_bytes();
                    let _ = stream.write_all(&out_len).await;
                    let _ = stream.write_all(&bytes).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Ok(port)
    }

    fn a_record(name: &str, ip: Ipv4Addr) -> Record {
        Record::from_rdata(Name::from_ascii(name).expect("name"), 60, RData::A(A(ip)))
    }

    fn aaaa_record(name: &str, ip: Ipv6Addr) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).expect("name"),
            60,
            RData::AAAA(AAAA(ip)),
        )
    }

    fn mx_record(name: &str, preference: u16, exchange: &str) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).expect("name"),
            60,
            RData::MX(MX::new(preference, Name::from_ascii(exchange).expect("mx"))),
        )
    }

    fn txt_record(name: &str, text: &str) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).expect("name"),
            60,
            RData::TXT(TXT::new(vec![text.to_string()])),
        )
    }

    fn ns_record(name: &str, target: &str) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).expect("name"),
            60,
            RData::NS(NS(Name::from_ascii(target).expect("target"))),
        )
    }

    fn cname_record(name: &str, target: &str) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).expect("name"),
            60,
            RData::CNAME(CNAME(Name::from_ascii(target).expect("target"))),
        )
    }

    fn ptr_record(name: &str, target: &str) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).expect("name"),
            60,
            RData::PTR(PTR(Name::from_ascii(target).expect("target"))),
        )
    }

    fn make_prober(ports: Vec<u16>, qtype: DnsQueryType, transport: DnsTransport) -> DnsProber {
        DnsProber::new(
            ports,
            vec!["example.com.".to_string()],
            qtype,
            transport,
            true,
        )
        .expect("valid")
    }

    #[tokio::test]
    async fn dns_prober_emits_signal_for_a_record() {
        let port = spawn_udp_dns_server(
            "127.0.0.1:0",
            DnsResponder(Arc::new(|q| {
                let ans = vec![a_record(
                    &q.name().to_ascii(),
                    Ipv4Addr::new(93, 184, 216, 34),
                )];
                (ans, ResponseCode::NoError)
            })),
        )
        .await
        .expect("bind");
        let prober = make_prober(vec![port], DnsQueryType::A, DnsTransport::Udp);
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(
            &outcome.signals[0],
            Signal::DnsHost(s) if s == "example.com. -> 93.184.216.34"
        ));
        assert_eq!(outcome.kind, ProbeKind::Dns);
    }

    #[tokio::test]
    async fn dns_prober_emits_multiple_signals_for_multi_record_response() {
        let port = spawn_udp_dns_server(
            "127.0.0.1:0",
            DnsResponder(Arc::new(|q| {
                let name = q.name().to_ascii();
                let ans = vec![
                    a_record(&name, Ipv4Addr::new(93, 184, 216, 34)),
                    a_record(&name, Ipv4Addr::new(93, 184, 216, 35)),
                ];
                (ans, ResponseCode::NoError)
            })),
        )
        .await
        .expect("bind");
        let prober = make_prober(vec![port], DnsQueryType::A, DnsTransport::Udp);
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 2);
        assert!(matches!(
            &outcome.signals[0],
            Signal::DnsHost(s) if s == "example.com. -> 93.184.216.34"
        ));
        assert!(matches!(
            &outcome.signals[1],
            Signal::DnsHost(s) if s == "example.com. -> 93.184.216.35"
        ));
    }

    #[tokio::test]
    async fn dns_prober_emits_signal_for_mx_record() {
        let port = spawn_udp_dns_server(
            "127.0.0.1:0",
            DnsResponder(Arc::new(|q| {
                let ans = vec![mx_record(&q.name().to_ascii(), 10, "mail.example.com.")];
                (ans, ResponseCode::NoError)
            })),
        )
        .await
        .expect("bind");
        let prober = make_prober(vec![port], DnsQueryType::Mx, DnsTransport::Udp);
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(
            &outcome.signals[0],
            Signal::DnsHost(s) if s == "example.com. -> 10 mail.example.com."
        ));
    }

    #[tokio::test]
    async fn dns_prober_emits_signal_for_txt_record() {
        let port = spawn_udp_dns_server(
            "127.0.0.1:0",
            DnsResponder(Arc::new(|q| {
                let ans = vec![txt_record(&q.name().to_ascii(), "v=spf1 -all")];
                (ans, ResponseCode::NoError)
            })),
        )
        .await
        .expect("bind");
        let prober = make_prober(vec![port], DnsQueryType::Txt, DnsTransport::Udp);
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(
            &outcome.signals[0],
            Signal::DnsHost(s) if s == "example.com. -> \"v=spf1 -all\""
        ));
    }

    #[tokio::test]
    async fn dns_prober_emits_signal_for_ns_and_cname_records() {
        let ns_port = spawn_udp_dns_server(
            "127.0.0.1:0",
            DnsResponder(Arc::new(|q| {
                let ans = vec![ns_record(&q.name().to_ascii(), "ns1.example.com.")];
                (ans, ResponseCode::NoError)
            })),
        )
        .await
        .expect("bind");
        let ns_prober = make_prober(vec![ns_port], DnsQueryType::Ns, DnsTransport::Udp);
        let ns_outcome = ns_prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(matches!(
            ns_outcome.signals.first(),
            Some(Signal::DnsHost(s)) if s == "example.com. -> ns1.example.com."
        ));

        let cname_port = spawn_udp_dns_server(
            "127.0.0.1:0",
            DnsResponder(Arc::new(|q| {
                let ans = vec![cname_record(&q.name().to_ascii(), "www.example.com.")];
                (ans, ResponseCode::NoError)
            })),
        )
        .await
        .expect("bind");
        let cname_prober = make_prober(vec![cname_port], DnsQueryType::Cname, DnsTransport::Udp);
        let cname_outcome = cname_prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(matches!(
            cname_outcome.signals.first(),
            Some(Signal::DnsHost(s)) if s == "example.com. -> www.example.com."
        ));
    }

    #[tokio::test]
    async fn dns_prober_emits_signal_for_ptr_record() {
        let port = spawn_udp_dns_server(
            "127.0.0.1:0",
            DnsResponder(Arc::new(|q| {
                let ans = vec![ptr_record(&q.name().to_ascii(), "localhost.")];
                (ans, ResponseCode::NoError)
            })),
        )
        .await
        .expect("bind");
        let prober = DnsProber::new(
            vec![port],
            vec!["1.0.0.127.in-addr.arpa.".to_string()],
            DnsQueryType::Ptr,
            DnsTransport::Udp,
            true,
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(matches!(
            outcome.signals.first(),
            Some(Signal::DnsHost(s)) if s == "1.0.0.127.in-addr.arpa. -> localhost."
        ));
    }

    #[tokio::test]
    async fn dns_prober_marks_reachable_on_nxdomain_but_emits_no_signal() {
        let port = spawn_udp_dns_server(
            "127.0.0.1:0",
            DnsResponder(Arc::new(|_q| (Vec::new(), ResponseCode::NXDomain))),
        )
        .await
        .expect("bind");
        let prober = make_prober(vec![port], DnsQueryType::A, DnsTransport::Udp);
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn dns_prober_marks_reachable_on_refused_but_emits_no_signal() {
        let port = spawn_udp_dns_server(
            "127.0.0.1:0",
            DnsResponder(Arc::new(|_q| (Vec::new(), ResponseCode::Refused))),
        )
        .await
        .expect("bind");
        let prober = make_prober(vec![port], DnsQueryType::A, DnsTransport::Udp);
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn dns_prober_maps_timeout_to_unreachable_outcome() {
        // Bind a UDP socket that never responds. The hickory resolver will retry
        // until the outer tokio::time::timeout fires.
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        let _hold = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let _ = socket.recv_from(&mut buf).await;
                // Do not respond.
            }
        });
        let prober = make_prober(vec![port], DnsQueryType::A, DnsTransport::Udp);
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(200))
            .await
            .expect("a silent server is an outcome, not an error");
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn dns_prober_maps_closed_udp_port_to_unreachable_outcome() {
        // Bind and drop a UDP port: sending to it yields ECONNREFUSED via ICMP
        // port unreachable, observable on the connected socket.
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        drop(socket);
        let prober = make_prober(vec![port], DnsQueryType::A, DnsTransport::Udp);
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(500))
            .await
            .expect("a closed port is an outcome, not an error");
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn dns_prober_ipv6_target() {
        let port = match spawn_udp_dns_server(
            "[::1]:0",
            DnsResponder(Arc::new(|q| {
                let ans = vec![aaaa_record(
                    &q.name().to_ascii(),
                    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                )];
                (ans, ResponseCode::NoError)
            })),
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("skipping IPv6 test: IPv6 loopback bind failed: {e}");
                return;
            }
        };
        let ip: IpAddr = "::1".parse().expect("::1");
        let target = ResolvedTarget {
            ip,
            original: Target::Ip(ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        };
        let prober = make_prober(vec![port], DnsQueryType::Aaaa, DnsTransport::Udp);
        let outcome = prober
            .probe(&target, &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert!(matches!(
            outcome.signals.first(),
            Some(Signal::DnsHost(s)) if s == "example.com. -> 2001:db8::1"
        ));
    }

    #[tokio::test]
    async fn dns_prober_tcp_transport_captures_a_record() {
        let port = spawn_tcp_dns_server(
            "127.0.0.1:0",
            DnsResponder(Arc::new(|q| {
                let ans = vec![a_record(
                    &q.name().to_ascii(),
                    Ipv4Addr::new(93, 184, 216, 34),
                )];
                (ans, ResponseCode::NoError)
            })),
        )
        .await
        .expect("bind");
        let prober = make_prober(vec![port], DnsQueryType::A, DnsTransport::Tcp);
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert!(matches!(
            outcome.signals.first(),
            Some(Signal::DnsHost(s)) if s == "example.com. -> 93.184.216.34"
        ));
    }

    #[tokio::test]
    async fn dns_prober_multi_port_probes_all_ports() {
        let responder = DnsResponder(Arc::new(|q| {
            let ans = vec![a_record(&q.name().to_ascii(), Ipv4Addr::new(10, 0, 0, 1))];
            (ans, ResponseCode::NoError)
        }));
        let port_a = spawn_udp_dns_server("127.0.0.1:0", responder.clone())
            .await
            .expect("bind");
        let port_b = spawn_udp_dns_server("127.0.0.1:0", responder)
            .await
            .expect("bind");
        let prober = make_prober(vec![port_a, port_b], DnsQueryType::A, DnsTransport::Udp);
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        // Both ports should have contributed one signal each (same query name).
        assert_eq!(outcome.signals.len(), 2);
    }

    #[tokio::test]
    async fn dns_prober_multi_query_probes_all_names() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let counter = Arc::new(AtomicUsize::new(0));
        let ctr = counter.clone();
        let port = spawn_udp_dns_server(
            "127.0.0.1:0",
            DnsResponder(Arc::new(move |q| {
                ctr.fetch_add(1, Ordering::SeqCst);
                let ans = vec![a_record(&q.name().to_ascii(), Ipv4Addr::new(10, 0, 0, 1))];
                (ans, ResponseCode::NoError)
            })),
        )
        .await
        .expect("bind");
        let prober = DnsProber::new(
            vec![port],
            vec![
                "a.example.com.".to_string(),
                "b.example.com.".to_string(),
                "c.example.com.".to_string(),
            ],
            DnsQueryType::A,
            DnsTransport::Udp,
            true,
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert_eq!(outcome.signals.len(), 3);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn dns_prober_maps_undecodable_reply_to_a_probe_fault() {
        let port = spawn_garbage_udp_server().await;
        let prober = make_prober(vec![port], DnsQueryType::A, DnsTransport::Udp);
        let err = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect_err("a reply we cannot decode is a fault, not an absent host");
        match err {
            RastreoError::Probe(ProbeError::Other(msg)) => {
                assert!(msg.contains("dns probe failed"), "got: {msg}");
            }
            other => panic!("expected ProbeError::Other, got {other:?}"),
        }
    }

    async fn spawn_garbage_udp_server() -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (_, peer) = match socket.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let _ = socket.send_to(b"not a dns message", peer).await;
            }
        });
        port
    }

    #[test]
    fn dns_query_type_deserializes_snake_case() {
        for (input, expected) in [
            ("a", DnsQueryType::A),
            ("aaaa", DnsQueryType::Aaaa),
            ("mx", DnsQueryType::Mx),
            ("txt", DnsQueryType::Txt),
            ("ptr", DnsQueryType::Ptr),
            ("ns", DnsQueryType::Ns),
            ("cname", DnsQueryType::Cname),
        ] {
            let parsed: DnsQueryType = serde_json::from_str(&format!("\"{input}\""))
                .unwrap_or_else(|e| panic!("deserialize {input}: {e}"));
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn dns_transport_deserializes_snake_case() {
        let udp: DnsTransport = serde_json::from_str("\"udp\"").expect("udp");
        assert_eq!(udp, DnsTransport::Udp);
        let tcp: DnsTransport = serde_json::from_str("\"tcp\"").expect("tcp");
        assert_eq!(tcp, DnsTransport::Tcp);
    }

    #[test]
    fn new_rejects_empty_query_names() {
        match DnsProber::new(
            vec![53],
            Vec::new(),
            DnsQueryType::A,
            DnsTransport::Udp,
            true,
        ) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("query_name"), "got: {msg}");
            }
            Err(other) => panic!("expected InvalidValue, got {other:?}"),
            Ok(_) => panic!("must error"),
        }
    }

    #[test]
    fn new_rejects_empty_ports() {
        match DnsProber::new(
            Vec::new(),
            vec!["example.com".to_string()],
            DnsQueryType::A,
            DnsTransport::Udp,
            true,
        ) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("port"), "got: {msg}");
            }
            Err(other) => panic!("expected InvalidValue, got {other:?}"),
            Ok(_) => panic!("must error"),
        }
    }

    #[test]
    fn new_rejects_invalid_label_length() {
        let long_label = "a".repeat(64);
        match DnsProber::new(
            vec![53],
            vec![format!("{long_label}.example.com")],
            DnsQueryType::A,
            DnsTransport::Udp,
            true,
        ) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("label"), "got: {msg}");
            }
            Err(other) => panic!("expected InvalidValue, got {other:?}"),
            Ok(_) => panic!("must error"),
        }
    }

    #[test]
    fn new_rejects_too_long_name() {
        // 4 labels of 63 chars + 3 dots = 255 > 253
        let label = "a".repeat(63);
        let name = format!("{label}.{label}.{label}.{label}");
        match DnsProber::new(
            vec![53],
            vec![name],
            DnsQueryType::A,
            DnsTransport::Udp,
            true,
        ) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("bytes"), "got: {msg}");
            }
            Err(other) => panic!("expected InvalidValue, got {other:?}"),
            Ok(_) => panic!("must error"),
        }
    }

    #[test]
    fn new_rejects_empty_label_in_name() {
        match DnsProber::new(
            vec![53],
            vec!["foo..bar".to_string()],
            DnsQueryType::A,
            DnsTransport::Udp,
            true,
        ) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("empty label"), "got: {msg}");
            }
            Err(other) => panic!("expected InvalidValue, got {other:?}"),
            Ok(_) => panic!("must error"),
        }
    }

    #[test]
    fn new_sorts_and_dedups_ports() {
        let prober = DnsProber::new(
            vec![53, 5353, 53, 853],
            vec!["example.com".to_string()],
            DnsQueryType::A,
            DnsTransport::Udp,
            true,
        )
        .expect("valid");
        assert_eq!(prober.ports(), &[53, 853, 5353]);
    }

    #[test]
    fn kind_returns_dns() {
        let prober = DnsProber::new(
            vec![53],
            vec!["example.com".to_string()],
            DnsQueryType::A,
            DnsTransport::Udp,
            true,
        )
        .expect("valid");
        assert_eq!(prober.kind(), ProbeKind::Dns);
    }

    #[test]
    fn default_ports_returns_port_53() {
        assert_eq!(default_ports(), vec![53]);
    }

    #[test]
    fn default_recursion_desired_is_true() {
        assert!(default_recursion_desired());
    }

    #[test]
    fn dns_prober_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<DnsProber>();
        assert_send_sync::<Box<dyn Prober>>();
    }

    #[test]
    fn accessors_expose_configuration() {
        let prober = DnsProber::new(
            vec![53, 5353],
            vec!["example.com.".to_string(), "other.com.".to_string()],
            DnsQueryType::Mx,
            DnsTransport::Tcp,
            false,
        )
        .expect("valid");
        assert_eq!(prober.query_names().len(), 2);
        assert_eq!(prober.query_type(), DnsQueryType::Mx);
        assert_eq!(prober.transport(), DnsTransport::Tcp);
        assert!(!prober.recursion_desired());
    }
}
