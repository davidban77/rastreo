//! The reachability contract every prober implements. A target that does not answer is
//! `Ok(ProbeOutcome { reachable: false, signals: [] })`; a fault is carried as a typed
//! `ProbeOutcome::fault`, never discarded as an `Err`. Both halves are load-bearing: a fault
//! booked as absence hides a broken probe behind a dark host, and absence booked as a fault
//! floods a scan with errors for every port that is simply closed.
//!
//! The fleet walk below is driven by `ProbeKind::all()`, so a new `ProbeKind` fails this suite
//! until it declares BOTH halves of the contract in `contract_for`.
//!
//! Probers whose fault needs a privileged socket or a local resource failure (descriptor
//! exhaustion, a denied capability) cannot induce it in-process; those declare the unit-test
//! seam that covers them instead.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime};

use rastreo_core::model::{ProbeCtx, ProbeKind, ResolvedTarget, Target};
use rastreo_core::prober::{create_prober, DnsQueryType, DnsTransport, ProberConfig, UdpProtocol};
use rastreo_core::ProbeErrorKind;

/// TEST-NET-1 (RFC 5737): routable nowhere, answers nothing.
const DARK_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
/// TEST-NET-2 (RFC 5737): has no PTR anywhere.
const UNNAMED_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

struct Contract {
    absence: Absence,
    fault: Fault,
}

enum Absence {
    /// Asserted by the fleet walk: probe a target that does not answer.
    Probe {
        config: ProberConfig,
        target: IpAddr,
    },
    /// Not assertable in-process; the named seam is the contract record.
    Seam(&'static str),
}

enum Fault {
    /// Asserted by the fleet walk: probe a target that breaks the probe. `expect_kind` is the
    /// [`ProbeErrorKind`] the resulting `ProbeOutcome::fault` must carry.
    Probe {
        config: ProberConfig,
        target: IpAddr,
        expect_kind: ProbeErrorKind,
    },
    /// Not assertable in-process; the named seam is the contract record.
    Seam(&'static str),
}

fn absent(config: ProberConfig, target: IpAddr) -> Absence {
    Absence::Probe { config, target }
}

/// The shared-engine fault paths — a failed socket open (no `CAP_NET_RAW`) and a dead reader —
/// cannot be induced on a host that grants the capability, so the named unit tests are the record:
/// an open failure is cached and faults every probe, and reader death poisons in-flight waiters.
#[cfg(feature = "icmp")]
const ICMP_FAULT_SEAM: &str =
    "seams: icmp::get_or_open_caches_an_open_failure_and_faults_every_probe_without_re_opening, \
     icmp::open_fault_outcome_is_an_unreachable_kinded_fault_with_no_signals, \
     icmp::dropping_reader_exit_poisons_the_demux_and_faults_the_waiter, \
     icmp::a_poison_delivered_during_send_outranks_an_absence_classified_send_error, \
     icmp::a_poisoned_engine_wakes_a_waiter_with_a_fault_not_absence";

async fn contract_for(kind: ProbeKind) -> Contract {
    match kind {
        ProbeKind::TcpConnect => Contract {
            absence: absent(
                ProberConfig::TcpConnect {
                    ports: vec![closed_tcp_port().await],
                },
                LOOPBACK,
            ),
            fault: Fault::Seam(
                "descriptor exhaustion / a denied capability is not inducible in-process; \
                 seam: tcp_connect::no_signals_and_a_connect_fault_is_a_kinded_fault_outcome",
            ),
        },
        ProbeKind::Udp => Contract {
            absence: absent(
                ProberConfig::Udp {
                    ports: vec![closed_udp_port().await],
                    protocol: UdpProtocol::Ntp,
                },
                LOOPBACK,
            ),
            fault: Fault::Seam(
                "a local socket failure on bind/send is not inducible in-process; \
                 seam: udp::no_answer_and_a_socket_fault_is_a_kinded_fault_outcome",
            ),
        },
        ProbeKind::Dns => Contract {
            absence: absent(dns_config(closed_udp_port().await), LOOPBACK),
            fault: Fault::Probe {
                config: dns_config(garbage_udp_port().await),
                target: LOOPBACK,
                expect_kind: ProbeErrorKind::DnsFailed,
            },
        },
        // Not loopback: hickory answers the loopback reverse zone from its built-in RFC 6761
        // localhost zone, so 127.0.0.1 has a PTR without any server replying.
        ProbeKind::ReverseDns => Contract {
            absence: absent(
                ProberConfig::ReverseDns {
                    resolvers: vec![DARK_IP],
                },
                UNNAMED_IP,
            ),
            // The config carries resolver IPs only (port 53 implied), so a stub resolver is not
            // reachable from here.
            fault: Fault::Seam(
                "resolver port is not configurable; \
                 seam: reverse_dns::probe_maps_an_undecodable_reply_to_a_probe_fault",
            ),
        },
        // A peer that will not negotiate TLS is not an http fault: the connect completed, so the
        // probe keeps the `OpenPort` it earned. Only a connect that fails locally learns nothing.
        #[cfg(feature = "http")]
        ProbeKind::Http => Contract {
            absence: absent(http_config(closed_tcp_port().await), LOOPBACK),
            fault: Fault::Seam(
                "descriptor exhaustion / a denied capability is not inducible in-process; \
                 seam: http::no_open_port_and_a_connect_fault_is_a_kinded_fault_outcome",
            ),
        },
        #[cfg(not(feature = "http"))]
        ProbeKind::Http => Contract {
            absence: Absence::Seam("http feature disabled"),
            fault: Fault::Seam("http feature disabled"),
        },
        #[cfg(feature = "snmp")]
        ProbeKind::Snmp => Contract {
            absence: absent(snmp_config(closed_udp_port().await), LOOPBACK),
            fault: Fault::Probe {
                config: snmp_config(garbage_udp_port().await),
                target: LOOPBACK,
                expect_kind: ProbeErrorKind::DecodeFailed,
            },
        },
        #[cfg(not(feature = "snmp"))]
        ProbeKind::Snmp => Contract {
            absence: Absence::Seam("snmp feature disabled"),
            fault: Fault::Seam("snmp feature disabled"),
        },
        #[cfg(feature = "ssh")]
        ProbeKind::Ssh => Contract {
            absence: absent(
                ProberConfig::Ssh {
                    ports: vec![closed_tcp_port().await],
                },
                LOOPBACK,
            ),
            fault: Fault::Seam(
                "descriptor exhaustion / a denied capability is not inducible in-process; \
                 seam: ssh::no_open_port_and_a_connect_fault_is_a_kinded_fault_outcome",
            ),
        },
        #[cfg(not(feature = "ssh"))]
        ProbeKind::Ssh => Contract {
            absence: Absence::Seam("ssh feature disabled"),
            fault: Fault::Seam("ssh feature disabled"),
        },
        // A peer that will not negotiate is not a tls fault: the port answered, so the probe keeps
        // the `OpenPort` it earned. Only a connect that fails locally learns nothing.
        #[cfg(feature = "tls")]
        ProbeKind::Tls => Contract {
            absence: absent(
                ProberConfig::Tls {
                    ports: vec![closed_tcp_port().await],
                },
                LOOPBACK,
            ),
            fault: Fault::Seam(
                "descriptor exhaustion / a denied capability is not inducible in-process; \
                 seam: tls::no_open_port_and_a_connect_fault_is_a_kinded_fault_outcome",
            ),
        },
        #[cfg(not(feature = "tls"))]
        ProbeKind::Tls => Contract {
            absence: Absence::Seam("tls feature disabled"),
            fault: Fault::Seam("tls feature disabled"),
        },
        // A dgram ICMP socket is unprivileged on macOS; on Linux it needs the
        // ping_group_range sysctl or CAP_NET_RAW, neither of which CI grants.
        #[cfg(all(feature = "icmp", target_os = "macos"))]
        ProbeKind::Icmp => Contract {
            absence: absent(
                ProberConfig::Icmp {
                    count: 1,
                    interval_ms: 0,
                },
                DARK_IP,
            ),
            fault: Fault::Seam(ICMP_FAULT_SEAM),
        },
        #[cfg(all(feature = "icmp", not(target_os = "macos")))]
        ProbeKind::Icmp => Contract {
            absence: Absence::Seam(
                "a dgram icmp socket needs CAP_NET_RAW or the ping_group_range sysctl here; \
                 absence is asserted by this same walk on macOS, which grants it unprivileged",
            ),
            fault: Fault::Seam(ICMP_FAULT_SEAM),
        },
        #[cfg(not(feature = "icmp"))]
        ProbeKind::Icmp => Contract {
            absence: Absence::Seam("icmp feature disabled"),
            fault: Fault::Seam("icmp feature disabled"),
        },
        #[cfg(feature = "arp")]
        ProbeKind::Arp => Contract {
            absence: Absence::Seam(
                "privileged socket; \
                 seam: arp::timeout_resolution_is_an_unreachable_outcome_not_an_error",
            ),
            fault: Fault::Probe {
                config: ProberConfig::Arp {
                    interface: String::new(),
                },
                target: "2001:db8::1".parse().expect("valid ipv6"),
                expect_kind: ProbeErrorKind::Other,
            },
        },
        #[cfg(not(feature = "arp"))]
        ProbeKind::Arp => Contract {
            absence: Absence::Seam("arp feature disabled"),
            fault: Fault::Seam("arp feature disabled"),
        },
        #[cfg(feature = "ndp")]
        ProbeKind::Ndp => Contract {
            absence: Absence::Seam(
                "privileged socket; \
                 seam: ndp::timeout_resolution_is_an_unreachable_outcome_not_an_error",
            ),
            fault: Fault::Probe {
                config: ProberConfig::Ndp {
                    interface: String::new(),
                },
                target: LOOPBACK,
                expect_kind: ProbeErrorKind::Other,
            },
        },
        #[cfg(not(feature = "ndp"))]
        ProbeKind::Ndp => Contract {
            absence: Absence::Seam("ndp feature disabled"),
            fault: Fault::Seam("ndp feature disabled"),
        },
        _ => panic!(
            "{kind:?} has no reachability contract: declare both halves in contract_for() — how \
             it reports an absent target, and how it reports a fault — either as a probe case or \
             as a seam covered by the prober's unit tests"
        ),
    }
}

fn dns_config(port: u16) -> ProberConfig {
    ProberConfig::Dns {
        ports: vec![port],
        query_names: vec!["example.com".to_string()],
        query_type: DnsQueryType::A,
        transport: DnsTransport::Udp,
        recursion_desired: true,
    }
}

#[cfg(feature = "http")]
fn http_config(port: u16) -> ProberConfig {
    use rastreo_core::prober::http::{default_path, default_tls_verify, default_user_agent};
    use rastreo_core::prober::HttpScheme;

    ProberConfig::Http {
        ports: vec![port],
        scheme: HttpScheme::Https,
        path: default_path(),
        tls_verify: default_tls_verify(),
        user_agent: default_user_agent(),
    }
}

#[cfg(feature = "snmp")]
fn snmp_config(port: u16) -> ProberConfig {
    use rastreo_core::prober::{Community, SnmpVersion, UsmCredentials};

    ProberConfig::Snmp {
        ports: vec![port],
        version: SnmpVersion::V2c,
        community: Community("public".into()),
        credentials: UsmCredentials::default(),
    }
}

fn target_at(ip: IpAddr) -> ResolvedTarget {
    ResolvedTarget {
        ip,
        original: Target::Ip(ip),
        resolved_at: SystemTime::UNIX_EPOCH,
    }
}

fn ctx() -> ProbeCtx {
    ProbeCtx::new(Duration::from_millis(500), 0)
}

async fn closed_tcp_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

async fn closed_udp_port() -> u16 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = socket.local_addr().expect("addr").port();
    drop(socket);
    port
}

/// Answers every datagram with bytes that decode as neither DNS nor SNMP.
async fn garbage_udp_port() -> u16 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = socket.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (_, peer) = match socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => return,
            };
            let _ = socket.send_to(b"not a protocol message", peer).await;
        }
    });
    port
}

#[tokio::test]
async fn every_probe_kind_maps_absence_to_an_outcome() {
    for kind in ProbeKind::all() {
        match contract_for(*kind).await.absence {
            Absence::Probe { config, target } => {
                let prober = create_prober(&config).expect("factory builds prober");
                let outcome = prober
                    .probe(&target_at(target), &ctx())
                    .await
                    .unwrap_or_else(|err| {
                        panic!(
                            "{kind:?}: a target that does not answer must not be an error: {err}"
                        )
                    });
                assert_eq!(outcome.kind, *kind);
                assert_eq!(outcome.target_ip, target);
                assert!(
                    !outcome.reachable,
                    "{kind:?}: a target that does not answer is not reachable"
                );
                assert!(
                    outcome.signals.is_empty(),
                    "{kind:?}: an absent target yields no signals, got {:?}",
                    outcome.signals
                );
            }
            Absence::Seam(reason) => eprintln!("{kind:?}: absence not asserted here — {reason}"),
        }
    }
}

#[tokio::test]
async fn every_probe_kind_maps_a_fault_to_an_error() {
    for kind in ProbeKind::all() {
        match contract_for(*kind).await.fault {
            Fault::Probe {
                config,
                target,
                expect_kind,
            } => {
                let prober = create_prober(&config).expect("factory builds prober");
                let outcome = prober
                    .probe(&target_at(target), &ctx())
                    .await
                    .unwrap_or_else(|err| {
                        panic!("{kind:?}: a fault is data on the outcome, not an Err: {err}")
                    });
                let fault = outcome.fault.unwrap_or_else(|| {
                    panic!("{kind:?}: a broken probe must record a fault on the outcome")
                });
                assert_eq!(
                    fault.kind, expect_kind,
                    "{kind:?}: fault must be kinded {expect_kind:?}, got {:?} ({})",
                    fault.kind, fault.detail
                );
            }
            Fault::Seam(reason) => eprintln!("{kind:?}: fault not asserted here — {reason}"),
        }
    }
}
