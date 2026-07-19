use rasn::types::ObjectIdentifier;

use crate::model::ProbeCtx;

use super::request::{snmp_request, RequestPdu, SnmpError, SnmpResponse, SnmpSession, VarValue};

const DEFAULT_MAX_PDUS: usize = 512;
const DEFAULT_MAX_REPETITIONS: u32 = 20;
const V1_NO_SUCH_NAME: u32 = 2;

pub(crate) struct WalkBounds {
    pub(crate) max_rows: usize,
    pub(crate) max_pdus: usize,
    pub(crate) max_repetitions: u32,
}

impl WalkBounds {
    pub(crate) fn new(max_rows: usize) -> Self {
        Self {
            max_rows,
            max_pdus: DEFAULT_MAX_PDUS,
            max_repetitions: DEFAULT_MAX_REPETITIONS,
        }
    }
}

/// Walk the subtree rooted at `base_oid`, returning `(OID, value)` rows in lexicographic order.
/// GETBULK on v2c/v3, GETNEXT on v1. Stops on subtree-exit, `EndOfMibView`, v1 `noSuchName`,
/// `max_rows`/`max_pdus`, or the `ctx.timeout` deadline; skips `NoSuchObject`/`NoSuchInstance`
/// holes. A request error is propagated only before any row is collected; a mid-walk error returns
/// the rows gathered so far.
pub(crate) async fn walk(
    session: &SnmpSession,
    base_oid: &ObjectIdentifier,
    bounds: &WalkBounds,
    ctx: &ProbeCtx,
) -> Result<Vec<(ObjectIdentifier, VarValue)>, SnmpError> {
    let overall_deadline = tokio::time::Instant::now() + ctx.timeout;
    let use_bulk = session.supports_getbulk();
    let mut rows: Vec<(ObjectIdentifier, VarValue)> = Vec::new();
    let mut next = base_oid.clone();

    for _ in 0..bounds.max_pdus {
        let remaining = overall_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let mut req_ctx = ctx.clone();
        req_ctx.timeout = remaining;

        let pdu = if use_bulk {
            RequestPdu::GetBulk {
                non_repeaters: 0,
                max_repetitions: bounds.max_repetitions,
                names: vec![next.clone()],
            }
        } else {
            RequestPdu::GetNext(vec![next.clone()])
        };

        let resp = match snmp_request(session, &pdu, &req_ctx).await {
            Ok(resp) => resp,
            Err(e) if rows.is_empty() => return Err(e),
            Err(_) => break,
        };

        match absorb_batch(base_oid, &resp, !use_bulk, &mut rows, bounds.max_rows) {
            WalkStep::Continue(next_oid) => next = next_oid,
            WalkStep::Stop => break,
        }
    }
    Ok(rows)
}

enum WalkStep {
    Continue(ObjectIdentifier),
    Stop,
}

fn absorb_batch(
    base_oid: &ObjectIdentifier,
    resp: &SnmpResponse,
    is_v1: bool,
    rows: &mut Vec<(ObjectIdentifier, VarValue)>,
    max_rows: usize,
) -> WalkStep {
    // A v1 GETNEXT walking off the end of the MIB answers noSuchName.
    if is_v1 && resp.error_status == V1_NO_SUCH_NAME {
        return WalkStep::Stop;
    }
    let mut last: Option<ObjectIdentifier> = None;
    for vb in &resp.var_binds {
        // A returned OID that leaves the requested subtree is the walk's end — the primary stop.
        if !oid_within_subtree(base_oid, &vb.name) {
            return WalkStep::Stop;
        }
        match &vb.value {
            VarValue::EndOfMibView => return WalkStep::Stop,
            VarValue::NoSuchObject | VarValue::NoSuchInstance => {
                last = Some(vb.name.clone());
            }
            value => {
                rows.push((vb.name.clone(), value.clone()));
                last = Some(vb.name.clone());
                if rows.len() >= max_rows {
                    return WalkStep::Stop;
                }
            }
        }
    }
    match last {
        Some(oid) => WalkStep::Continue(oid),
        None => WalkStep::Stop,
    }
}

fn oid_within_subtree(base: &ObjectIdentifier, oid: &ObjectIdentifier) -> bool {
    let base: &[u32] = base.as_ref();
    let oid: &[u32] = oid.as_ref();
    oid.len() > base.len() && &oid[..base.len()] == base
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(arcs: &[u32]) -> ObjectIdentifier {
        ObjectIdentifier::new_unchecked(arcs.to_vec().into())
    }

    fn resp(error_status: u32, binds: Vec<(ObjectIdentifier, VarValue)>) -> SnmpResponse {
        SnmpResponse {
            error_status,
            var_binds: binds
                .into_iter()
                .map(|(name, value)| super::super::request::VarBind { name, value })
                .collect(),
        }
    }

    #[test]
    fn absorb_stops_when_an_oid_leaves_the_subtree() {
        let base = oid(&[1, 3, 6, 1]);
        let r = resp(
            0,
            vec![(oid(&[1, 3, 7, 0]), VarValue::Bytes(b"x".to_vec()))],
        );
        let mut rows = Vec::new();
        assert!(matches!(
            absorb_batch(&base, &r, false, &mut rows, 4096),
            WalkStep::Stop
        ));
        assert!(rows.is_empty(), "a subtree-exit row is not collected");
    }

    #[test]
    fn absorb_stops_on_end_of_mib_view_without_collecting_it() {
        let base = oid(&[1, 3, 6, 1]);
        let r = resp(0, vec![(oid(&[1, 3, 6, 1, 9]), VarValue::EndOfMibView)]);
        let mut rows = Vec::new();
        assert!(matches!(
            absorb_batch(&base, &r, false, &mut rows, 4096),
            WalkStep::Stop
        ));
        assert!(rows.is_empty());
    }

    #[test]
    fn absorb_caps_at_max_rows() {
        let base = oid(&[1, 3, 6, 1]);
        let r = resp(
            0,
            vec![
                (oid(&[1, 3, 6, 1, 1]), VarValue::Bytes(b"a".to_vec())),
                (oid(&[1, 3, 6, 1, 2]), VarValue::Bytes(b"b".to_vec())),
            ],
        );
        let mut rows = Vec::new();
        assert!(matches!(
            absorb_batch(&base, &r, false, &mut rows, 1),
            WalkStep::Stop
        ));
        assert_eq!(rows.len(), 1, "the walk stops the instant max_rows is hit");
    }

    #[test]
    fn absorb_skips_holes_without_aborting() {
        let base = oid(&[1, 3, 6, 1]);
        let r = resp(
            0,
            vec![
                (oid(&[1, 3, 6, 1, 1]), VarValue::Bytes(b"a".to_vec())),
                (oid(&[1, 3, 6, 1, 2]), VarValue::NoSuchInstance),
                (oid(&[1, 3, 6, 1, 3]), VarValue::Bytes(b"c".to_vec())),
            ],
        );
        let mut rows = Vec::new();
        match absorb_batch(&base, &r, false, &mut rows, 4096) {
            WalkStep::Continue(next) => assert_eq!(next.as_ref() as &[u32], &[1, 3, 6, 1, 3]),
            WalkStep::Stop => panic!("a hole must not abort the walk"),
        }
        assert_eq!(rows.len(), 2, "the two present cells are collected");
    }

    #[test]
    fn absorb_stops_on_v1_no_such_name() {
        let base = oid(&[1, 3, 6, 1]);
        let r = resp(
            V1_NO_SUCH_NAME,
            vec![(oid(&[1, 3, 6, 1, 1]), VarValue::Bytes(b"a".to_vec()))],
        );
        let mut rows = Vec::new();
        assert!(matches!(
            absorb_batch(&base, &r, true, &mut rows, 4096),
            WalkStep::Stop
        ));
        assert!(
            rows.is_empty(),
            "noSuchName ends a v1 walk before collecting"
        );
    }

    #[test]
    fn absorb_stops_when_the_agent_returns_nothing() {
        let base = oid(&[1, 3, 6, 1]);
        let r = resp(0, Vec::new());
        let mut rows = Vec::new();
        assert!(matches!(
            absorb_batch(&base, &r, false, &mut rows, 4096),
            WalkStep::Stop
        ));
    }

    #[test]
    fn absorb_advances_to_the_greatest_oid_in_the_batch() {
        let base = oid(&[1, 3, 6, 1]);
        let r = resp(
            0,
            vec![
                (oid(&[1, 3, 6, 1, 4, 1]), VarValue::Int(4)),
                (oid(&[1, 3, 6, 1, 5, 1]), VarValue::Int(5)),
            ],
        );
        let mut rows = Vec::new();
        match absorb_batch(&base, &r, false, &mut rows, 4096) {
            WalkStep::Continue(next) => assert_eq!(next.as_ref() as &[u32], &[1, 3, 6, 1, 5, 1]),
            WalkStep::Stop => panic!("a full batch continues from its last OID"),
        }
    }

    mod driver {
        use super::oid;
        use super::*;
        use crate::prober::snmp::SnmpVersion;
        use rasn::types::{Integer, OctetString};
        use rasn_smi::v2 as smi_v2;
        use rasn_snmp::{v2 as snmp_v2, v2c};
        use std::net::SocketAddr;
        use std::time::Duration;
        use tokio::net::UdpSocket;

        const TABLE_BASE: &[u32] = &[1, 3, 6, 1, 4, 1, 42, 1];

        // Sorted table with three rows plus a sentinel OID that leaves the subtree.
        fn table() -> Vec<(Vec<u32>, Vec<u8>)> {
            vec![
                (vec![1, 3, 6, 1, 4, 1, 42, 1, 2, 1], b"row-1".to_vec()),
                (vec![1, 3, 6, 1, 4, 1, 42, 1, 2, 2], b"row-2".to_vec()),
                (vec![1, 3, 6, 1, 4, 1, 42, 1, 2, 3], b"row-3".to_vec()),
                // outside the subtree — the walk must stop here without collecting it
                (vec![1, 3, 6, 1, 4, 1, 42, 2, 0], b"sentinel".to_vec()),
            ]
        }

        fn bulk_response(req: &[u8]) -> Option<Vec<u8>> {
            let msg: v2c::Message<snmp_v2::Pdus> = rasn::ber::decode(req).ok()?;
            let bulk = match msg.data {
                snmp_v2::Pdus::GetBulkRequest(snmp_v2::GetBulkRequest(pdu)) => pdu,
                _ => return None,
            };
            let start: &[u32] = bulk.variable_bindings.first()?.name.as_ref();
            let start = start.to_vec();
            let max = bulk.max_repetitions.max(1) as usize;
            let rows = table();
            let mut varbinds = Vec::new();
            for (name, value) in rows.iter().filter(|(n, _)| *n > start).take(max) {
                varbinds.push(snmp_v2::VarBind {
                    name: ObjectIdentifier::new_unchecked(name.clone().into()),
                    value: snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::Simple(
                        smi_v2::SimpleSyntax::String(OctetString::from_slice(value)),
                    )),
                });
            }
            let resp: v2c::Message<snmp_v2::Pdus> = v2c::Message {
                version: Integer::from(v2c::Message::<()>::VERSION),
                community: msg.community,
                data: snmp_v2::Pdus::Response(snmp_v2::Response(snmp_v2::Pdu {
                    request_id: bulk.request_id,
                    error_status: 0,
                    error_index: 0,
                    variable_bindings: varbinds,
                })),
            };
            rasn::ber::encode(&resp).ok()
        }

        async fn spawn_table_agent() -> u16 {
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let port = socket.local_addr().expect("addr").port();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    let (n, peer) = match socket.recv_from(&mut buf).await {
                        Ok(x) => x,
                        Err(_) => return,
                    };
                    if let Some(resp) = bulk_response(&buf[..n]) {
                        let _ = socket.send_to(&resp, peer).await;
                    }
                }
            });
            port
        }

        #[tokio::test]
        async fn getbulk_walk_collects_the_table_and_stops_at_subtree_exit() {
            let port = spawn_table_agent().await;
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
            let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let session = SnmpSession::community(client, target, SnmpVersion::V2c, "public".into());
            let base = oid(TABLE_BASE);
            // max_repetitions 2 forces at least two GETBULK round-trips over the 3-row table.
            let mut bounds = WalkBounds::new(4096);
            bounds.max_repetitions = 2;
            let ctx = ProbeCtx::new(Duration::from_secs(2), 0);

            let rows = walk(&session, &base, &bounds, &ctx).await.expect("walk ok");
            let values: Vec<Vec<u8>> = rows
                .iter()
                .map(|(_, v)| match v {
                    VarValue::Bytes(b) => b.clone(),
                    _ => Vec::new(),
                })
                .collect();
            assert_eq!(
                values,
                vec![b"row-1".to_vec(), b"row-2".to_vec(), b"row-3".to_vec()],
                "the walk collects exactly the subtree rows, in order"
            );
        }
    }
}
