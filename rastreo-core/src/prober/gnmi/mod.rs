#[allow(clippy::all, clippy::pedantic, clippy::nursery)]
mod proto {
    include!("generated.rs");
}

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use tokio::time::timeout;
use tonic::metadata::AsciiMetadataValue;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Code, Request, Response, Status};

use crate::error::{ConfigError, ProbeErrorKind, RastreoError};
use crate::fuser::keys::canonical_mac_str;
use crate::model::{
    GnmiEndpoint, LldpNeighbor, LldpObservation, ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome,
    ResolvedTarget, Signal, Transport,
};
use crate::prober::accept_any_tls::AcceptAnyVerifier;
use crate::prober::classify::{self, Disposition};
use crate::prober::ports::{probe_ports, MAX_PORTS_IN_FLIGHT};
use crate::prober::redacted::Password;
use crate::prober::Prober;

use proto::gnmi::g_nmi_client::GNmiClient;
use proto::gnmi::{
    CapabilityRequest, CapabilityResponse, Encoding, GetRequest, GetResponse, ModelData, Path,
    PathElem, TypedValue, Update,
};

const MAX_VALUE_BYTES: usize = 256;

// IEEE 802.1AB subtypes the SNMP `lldp` path stores; the assembler correlates on these numeric
// values, so the gNMI parser maps OpenConfig identityref strings to the same numbers.
const CHASSIS_SUBTYPE_MAC: u32 = 4;
const CHASSIS_SUBTYPE_NETWORK_ADDRESS: u32 = 5;
const PORT_SUBTYPE_MAC: u32 = 3;
const PORT_SUBTYPE_NETWORK_ADDRESS: u32 = 4;

const LLDP_GET_PATHS: &[&str] = &[
    "/lldp/state/chassis-id",
    "/lldp/state/chassis-id-type",
    "/lldp/interfaces/interface[name=*]/neighbors/neighbor[id=*]/state/chassis-id",
    "/lldp/interfaces/interface[name=*]/neighbors/neighbor[id=*]/state/chassis-id-type",
    "/lldp/interfaces/interface[name=*]/neighbors/neighbor[id=*]/state/port-id",
    "/lldp/interfaces/interface[name=*]/neighbors/neighbor[id=*]/state/port-id-type",
    "/lldp/interfaces/interface[name=*]/neighbors/neighbor[id=*]/state/system-name",
    "/lldp/interfaces/interface[name=*]/neighbors/neighbor[id=*]/state/port-description",
];

pub fn default_ports() -> Vec<u16> {
    vec![57400]
}

pub fn default_plaintext() -> bool {
    false
}

pub fn default_lldp() -> bool {
    false
}

pub fn default_get_paths() -> Vec<String> {
    vec![
        "/system/state/hostname".to_string(),
        "/system/state/software-version".to_string(),
    ]
}

/// JsonSchema-facing default for the redacted `password` field: the plaintext empty string, not
/// the `<redacted:HHHHHHHH>` token `Password::default()` would serialize as.
pub fn default_password_schema() -> &'static str {
    ""
}

struct GnmiAuth {
    username: AsciiMetadataValue,
    password: AsciiMetadataValue,
}

pub struct GnmiProber {
    ports: Vec<u16>,
    plaintext: bool,
    get_paths: Vec<Path>,
    lldp: bool,
    lldp_paths: Vec<Path>,
    auth: Option<GnmiAuth>,
}

impl std::fmt::Debug for GnmiProber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GnmiProber")
            .field("ports", &self.ports)
            .field("plaintext", &self.plaintext)
            .field("authenticated", &self.auth.is_some())
            .field("get_paths", &self.get_paths.len())
            .field("lldp", &self.lldp)
            .finish()
    }
}

impl GnmiProber {
    pub fn new(
        ports: Vec<u16>,
        plaintext: bool,
        username: String,
        password: Password,
        get_paths: Vec<String>,
        lldp: bool,
    ) -> Result<Self, RastreoError> {
        if ports.is_empty() {
            return Err(ConfigError::invalid("gnmi prober requires at least one port").into());
        }
        let mut ports = ports;
        ports.sort_unstable();
        ports.dedup();

        // Reject credentials that are not valid gRPC metadata values here (a control character
        // fails `try_from`) so a bad value is a construction error, not a per-probe surprise. Only
        // meaningful when a username is set; anonymous probes send no metadata.
        let auth = if username.is_empty() {
            None
        } else {
            let username = AsciiMetadataValue::try_from(username.as_str()).map_err(|_| {
                ConfigError::invalid("gnmi username is not a valid gRPC metadata value")
            })?;
            let password = AsciiMetadataValue::try_from(password.expose()).map_err(|_| {
                ConfigError::invalid("gnmi password is not a valid gRPC metadata value")
            })?;
            Some(GnmiAuth { username, password })
        };

        let get_paths = get_paths.iter().map(|p| parse_path(p)).collect();
        let lldp_paths = if lldp {
            LLDP_GET_PATHS.iter().map(|p| parse_path(p)).collect()
        } else {
            Vec::new()
        };

        Ok(Self {
            ports,
            plaintext,
            get_paths,
            lldp,
            lldp_paths,
            auth,
        })
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    fn request<T>(&self, message: T) -> Request<T> {
        let mut req = Request::new(message);
        if let Some(auth) = &self.auth {
            req.metadata_mut().insert("username", auth.username.clone());
            req.metadata_mut().insert("password", auth.password.clone());
        }
        req
    }

    async fn connect(
        &self,
        ip: IpAddr,
        port: u16,
        ctx: &ProbeCtx,
    ) -> Result<Channel, ConnectError> {
        let host = if ip.is_ipv6() {
            format!("[{ip}]")
        } else {
            ip.to_string()
        };
        let scheme = if self.plaintext { "http" } else { "https" };
        let endpoint = Endpoint::from_shared(format!("{scheme}://{host}:{port}"))
            .map_err(|e| {
                ConnectError::Fault(ProbeFault::new(
                    ProbeErrorKind::Other,
                    format!("gnmi endpoint uri invalid on port {port}: {e}"),
                ))
            })?
            .connect_timeout(ctx.timeout)
            .timeout(ctx.timeout);

        let endpoint = if self.plaintext {
            endpoint
        } else {
            // `assume_http2(true)` accepts a TLS peer that does not ALPN-negotiate `h2`, the
            // permissive posture discovery needs; the accept-any verifier fingerprints, never trusts.
            let tls = ClientTlsConfig::new().assume_http2(true);
            endpoint
                .tls_config_with_verifier(tls, Arc::new(AcceptAnyVerifier))
                .map_err(|e| {
                    ConnectError::Fault(ProbeFault::new(
                        ProbeErrorKind::Other,
                        format!("gnmi tls config failed on port {port}: {e}"),
                    ))
                })?
        };

        match endpoint.connect().await {
            Ok(channel) => Ok(channel),
            Err(err) => Err(classify_connect_error(port, &err)),
        }
    }

    async fn probe_port(&self, ip: IpAddr, port: u16, ctx: &ProbeCtx) -> PortResult {
        let channel = match self.connect(ip, port, ctx).await {
            Ok(channel) => channel,
            Err(ConnectError::Absence) => return PortResult::Absence,
            Err(ConnectError::Fault(fault)) => return PortResult::Fault(fault),
        };

        let mut client = GNmiClient::new(channel);
        let mut acc = PortAccumulator::default();
        // No Capabilities answer leaves the fallback encoding.
        let mut get_encoding = select_get_encoding(&[]);

        match timeout(
            ctx.timeout,
            client.capabilities(self.request(CapabilityRequest::default())),
        )
        .await
        {
            Ok(Ok(response)) => {
                acc.answered = true;
                let response = response.into_inner();
                get_encoding = select_get_encoding(&response.supported_encodings);
                acc.advertised_encodings = render_encodings(&response.supported_encodings);
                collect_capability_signals(response, &mut acc.signals);
            }
            Ok(Err(gnmi_status)) => {
                acc.status.get_or_insert(gnmi_status);
            }
            Err(_) => {}
        }

        // The state Get and the /lldp Get are independent: an error on one leaves the other's
        // contribution intact, so a device that lacks the OpenConfig `/lldp` path still yields its
        // state signals (and vice-versa).
        if !self.get_paths.is_empty() {
            let request = self.request(GetRequest {
                path: self.get_paths.clone(),
                encoding: get_encoding,
                ..Default::default()
            });
            if let Ok(result) = timeout(ctx.timeout, client.get(request)).await {
                acc.record_get(result.map(Response::into_inner), GetHandler::State);
            }
        }

        if self.lldp {
            let request = self.request(GetRequest {
                path: self.lldp_paths.clone(),
                encoding: get_encoding,
                ..Default::default()
            });
            if let Ok(result) = timeout(ctx.timeout, client.get(request)).await {
                acc.record_get(result.map(Response::into_inner), GetHandler::Lldp);
            }
        }

        let transport = if self.plaintext {
            Transport::Plaintext
        } else {
            Transport::Tls
        };
        acc.into_result(port, transport)
    }
}

#[derive(Default)]
struct PortAccumulator {
    signals: Vec<Signal>,
    answered: bool,
    status: Option<Status>,
    lldp: Option<LldpObservation>,
    advertised_encodings: Vec<String>,
}

enum GetHandler {
    State,
    Lldp,
}

impl PortAccumulator {
    fn record_get(&mut self, result: Result<GetResponse, Status>, handler: GetHandler) {
        match result {
            Ok(response) => {
                self.answered = true;
                match handler {
                    GetHandler::State => collect_get_signals(response, &mut self.signals),
                    GetHandler::Lldp => self.lldp = Some(parse_lldp_response(response)),
                }
            }
            Err(status) => {
                self.status.get_or_insert(status);
            }
        }
    }

    fn into_result(self, port: u16, transport: Transport) -> PortResult {
        if self.answered {
            let endpoint = GnmiEndpoint {
                port,
                transport,
                advertised_encodings: self.advertised_encodings,
            };
            PortResult::Answered(self.signals, self.lldp, endpoint)
        } else if let Some(status) = self.status {
            PortResult::Status(status)
        } else {
            // The channel connected but no RPC produced an answer within the deadline: no
            // application-layer evidence this is a gNMI endpoint, so book it as absence.
            PortResult::Absence
        }
    }
}

enum ConnectError {
    Absence,
    Fault(ProbeFault),
}

enum PortResult {
    Answered(Vec<Signal>, Option<LldpObservation>, GnmiEndpoint),
    Status(Status),
    Absence,
    Fault(ProbeFault),
}

fn render_encodings(supported: &[i32]) -> Vec<String> {
    supported
        .iter()
        .filter_map(|e| Encoding::try_from(*e).ok())
        .map(|e| e.as_str_name().to_string())
        .collect()
}

/// Picks the `Get` encoding from Capabilities: `JSON_IETF` when advertised, else the first
/// renderable advertised encoding. The no-Capabilities fallback is `JSON_IETF`, not plain `JSON`,
/// which SR Linux and IOS-XR reject.
fn select_get_encoding(supported: &[i32]) -> i32 {
    let json_ietf = Encoding::JsonIetf as i32;
    if supported.is_empty() || supported.contains(&json_ietf) {
        return json_ietf;
    }
    supported
        .iter()
        .copied()
        .find(|&encoding| is_renderable_encoding(encoding))
        .unwrap_or(json_ietf)
}

fn is_renderable_encoding(encoding: i32) -> bool {
    matches!(
        Encoding::try_from(encoding),
        Ok(Encoding::Json | Encoding::Proto | Encoding::Ascii | Encoding::JsonIetf)
    )
}

fn parse_path(raw: &str) -> Path {
    let (origin, rest) = split_origin(raw);
    let elem = rest
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(parse_elem)
        .collect();
    Path {
        origin,
        elem,
        ..Default::default()
    }
}

// Origin only precedes the first "/"; a colon after that (e.g. in a key value) is not a separator.
fn split_origin(raw: &str) -> (String, &str) {
    let head = raw.split('/').next().unwrap_or("");
    match head.find(':') {
        Some(colon) => (raw[..colon].to_string(), &raw[colon + 1..]),
        None => (String::new(), raw),
    }
}

fn parse_elem(segment: &str) -> PathElem {
    // Unbalanced brackets or a missing name degrade to a literal element name; never panic.
    parse_keyed_elem(segment).unwrap_or_else(|| PathElem {
        name: segment.to_string(),
        ..Default::default()
    })
}

fn parse_keyed_elem(segment: &str) -> Option<PathElem> {
    let open = segment.find('[')?;
    let name = &segment[..open];
    if name.is_empty() {
        return None;
    }
    let mut key = HashMap::new();
    let mut remaining = &segment[open..];
    while !remaining.is_empty() {
        let inner = remaining.strip_prefix('[')?;
        let close = inner.find(']')?;
        let pair = &inner[..close];
        let eq = pair.find('=')?;
        let attribute = &pair[..eq];
        if attribute.is_empty() {
            return None;
        }
        key.insert(attribute.to_string(), pair[eq + 1..].to_string());
        remaining = &inner[close + 1..];
    }
    Some(PathElem {
        name: name.to_string(),
        key,
    })
}

fn classify_connect_error(port: u16, err: &tonic::transport::Error) -> ConnectError {
    // Recover the connector's errno from tonic's opaque transport error, exactly as http.rs does
    // for reqwest; a connect-phase failure with no recoverable io::Error defaults to absence.
    if let Some(io) = classify::io_error_in_chain(err) {
        return match classify::io_error(io) {
            Disposition::Fault(kind) => ConnectError::Fault(ProbeFault::new(
                kind,
                format!("gnmi connect failed on port {port}: {err}"),
            )),
            Disposition::Absence => ConnectError::Absence,
        };
    }
    ConnectError::Absence
}

fn collect_capability_signals(response: CapabilityResponse, signals: &mut Vec<Signal>) {
    let version = response.g_nmi_version.trim();
    if !version.is_empty() {
        signals.push(Signal::GnmiVersion(truncate(version)));
    }
    for model in &response.supported_models {
        if let Some(signal) = model_signal(model) {
            signals.push(signal);
        }
    }
    for encoding in response.supported_encodings {
        if let Ok(encoding) = Encoding::try_from(encoding) {
            signals.push(Signal::GnmiSupportedEncoding(
                encoding.as_str_name().to_string(),
            ));
        }
    }
}

fn model_signal(model: &ModelData) -> Option<Signal> {
    let name = model.name.trim();
    if name.is_empty() {
        return None;
    }
    let mut rendered = name.to_string();
    let version = model.version.trim();
    if !version.is_empty() {
        rendered.push(' ');
        rendered.push_str(version);
    }
    let org = model.organization.trim();
    if !org.is_empty() {
        rendered.push_str(" (");
        rendered.push_str(org);
        rendered.push(')');
    }
    Some(Signal::GnmiSupportedModel(truncate(&rendered)))
}

fn collect_get_signals(response: GetResponse, signals: &mut Vec<Signal>) {
    for notification in &response.notification {
        let prefix = notification.prefix.as_ref();
        for update in &notification.update {
            let path = render_path(prefix, update.path.as_ref());
            if path.is_empty() {
                continue;
            }
            if let Some(value) = update.val.as_ref().and_then(render_typed_value) {
                signals.push(Signal::GnmiState { path, value });
            }
        }
    }
}

fn render_path(prefix: Option<&Path>, path: Option<&Path>) -> String {
    let mut out = String::new();
    if let Some(prefix) = prefix {
        append_path(&mut out, prefix);
    }
    if let Some(path) = path {
        append_path(&mut out, path);
    }
    out
}

fn append_path(out: &mut String, path: &Path) {
    for elem in &path.elem {
        out.push('/');
        out.push_str(&elem.name);
        if !elem.key.is_empty() {
            let mut keys: Vec<(&String, &String)> = elem.key.iter().collect();
            keys.sort();
            for (key, value) in keys {
                out.push('[');
                out.push_str(key);
                out.push('=');
                out.push_str(value);
                out.push(']');
            }
        }
    }
}

fn render_typed_value(value: &TypedValue) -> Option<String> {
    use proto::gnmi::typed_value::Value;

    let rendered = match value.value.as_ref()? {
        Value::StringVal(s) => s.clone(),
        Value::IntVal(i) => i.to_string(),
        Value::UintVal(u) => u.to_string(),
        Value::BoolVal(b) => b.to_string(),
        Value::DoubleVal(d) => d.to_string(),
        Value::AsciiVal(s) => s.clone(),
        Value::JsonVal(bytes) | Value::JsonIetfVal(bytes) => {
            String::from_utf8_lossy(bytes).into_owned()
        }
        Value::LeaflistVal(array) => {
            let items: Vec<String> = array
                .element
                .iter()
                .filter_map(render_typed_value)
                .collect();
            if items.is_empty() {
                return None;
            }
            items.join(",")
        }
        _ => return None,
    };
    let trimmed = rendered.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(truncate(trimmed))
    }
}

fn truncate(raw: &str) -> String {
    if raw.len() <= MAX_VALUE_BYTES {
        return raw.to_string();
    }
    let mut end = MAX_VALUE_BYTES;
    while end > 0 && !raw.is_char_boundary(end) {
        end -= 1;
    }
    raw[..end].to_string()
}

/// Parses an OpenConfig `/lldp` Get into an [`LldpObservation`] tagged `gnmi`. Its own parser
/// (never `collect_get_signals`, which truncates values and mangles JSON blobs), tolerant of both
/// device return formats: one Update per resolved leaf, or a JSON_IETF subtree blob.
fn parse_lldp_response(response: GetResponse) -> LldpObservation {
    let mut builder = LldpBuilder::default();
    for notification in &response.notification {
        let prefix = notification.prefix.as_ref();
        for update in &notification.update {
            builder.ingest_update(prefix, update);
        }
    }
    builder.finish()
}

#[derive(Default)]
struct LldpBuilder {
    local_chassis_id: Option<String>,
    local_chassis_type: Option<String>,
    neighbors: BTreeMap<(String, String), NeighborBuilder>,
}

#[derive(Default)]
struct NeighborBuilder {
    chassis_id: Option<String>,
    chassis_type: Option<String>,
    port_id: Option<String>,
    port_type: Option<String>,
    system_name: Option<String>,
    port_description: Option<String>,
}

impl LldpBuilder {
    fn ingest_update(&mut self, prefix: Option<&Path>, update: &Update) {
        let elems = joined_elems(prefix, update.path.as_ref());
        let Some(value) = update.val.as_ref() else {
            return;
        };
        if let Some(json) = json_blob(value) {
            self.ingest_json(&elems, &json);
        } else if let Some(scalar) = scalar_value(value) {
            self.ingest_leaf(&elems, scalar);
        }
    }

    fn ingest_leaf(&mut self, elems: &[PathElem], value: String) {
        let leaf = elems.last().map_or("", |e| strip_module(&e.name));
        match (
            elem_key(elems, "interface", "name"),
            elem_key(elems, "neighbor", "id"),
        ) {
            (Some(interface), Some(id)) => {
                set_neighbor_leaf(
                    self.neighbors.entry((interface, id)).or_default(),
                    leaf,
                    value,
                );
            }
            _ => match leaf {
                "chassis-id" => self.local_chassis_id = Some(value),
                "chassis-id-type" => self.local_chassis_type = Some(value),
                _ => {}
            },
        }
    }

    fn ingest_json(&mut self, elems: &[PathElem], json: &serde_json::Value) {
        match (
            elem_key(elems, "interface", "name"),
            elem_key(elems, "neighbor", "id"),
        ) {
            (Some(interface), Some(id)) => {
                let state = stripped_get(json, "state").unwrap_or(json);
                apply_neighbor_state(self.neighbors.entry((interface, id)).or_default(), state);
            }
            _ => self.ingest_container_json(json),
        }
    }

    fn ingest_container_json(&mut self, json: &serde_json::Value) {
        let root = descend_lldp_wrapper(json);
        if let Some(state) = stripped_get(root, "state") {
            if let Some(v) = stripped_str(state, "chassis-id") {
                self.local_chassis_id = Some(v);
            }
            if let Some(v) = stripped_str(state, "chassis-id-type") {
                self.local_chassis_type = Some(v);
            }
        }
        let interfaces = stripped_get(root, "interfaces").unwrap_or(root);
        let Some(list) = stripped_get(interfaces, "interface").and_then(|v| v.as_array()) else {
            return;
        };
        for intf in list {
            let Some(name) = stripped_str(intf, "name") else {
                continue;
            };
            let neighbors = stripped_get(intf, "neighbors").unwrap_or(intf);
            let Some(nlist) = stripped_get(neighbors, "neighbor").and_then(|v| v.as_array()) else {
                continue;
            };
            for nbr in nlist {
                let Some(id) = stripped_str(nbr, "id") else {
                    continue;
                };
                let state = stripped_get(nbr, "state").unwrap_or(nbr);
                apply_neighbor_state(self.neighbors.entry((name.clone(), id)).or_default(), state);
            }
        }
    }

    fn finish(self) -> LldpObservation {
        let local_subtype =
            chassis_subtype_from_type(self.local_chassis_type.as_deref().unwrap_or(""));
        let local_chassis_id = canonical_chassis(
            local_subtype,
            self.local_chassis_id.as_deref().unwrap_or(""),
        );
        let mut neighbors = Vec::with_capacity(self.neighbors.len());
        for ((interface, _id), nbr) in self.neighbors {
            let chassis_subtype =
                chassis_subtype_from_type(nbr.chassis_type.as_deref().unwrap_or(""));
            let port_subtype = port_subtype_from_type(nbr.port_type.as_deref().unwrap_or(""));
            neighbors.push(LldpNeighbor {
                local_port: interface,
                remote_chassis_id: canonical_chassis(
                    chassis_subtype,
                    nbr.chassis_id.as_deref().unwrap_or(""),
                ),
                remote_chassis_subtype: chassis_subtype,
                remote_port_id: canonical_port(port_subtype, nbr.port_id.as_deref().unwrap_or("")),
                remote_port_subtype: port_subtype,
                remote_port_desc: nbr.port_description.filter(|s| !s.is_empty()),
                remote_sys_name: nbr.system_name.filter(|s| !s.is_empty()),
            });
        }
        LldpObservation {
            local_chassis_id,
            local_chassis_subtype: local_subtype,
            neighbors,
            discovered_via: "gnmi".to_string(),
        }
    }
}

fn set_neighbor_leaf(entry: &mut NeighborBuilder, leaf: &str, value: String) {
    match leaf {
        "chassis-id" => entry.chassis_id = Some(value),
        "chassis-id-type" => entry.chassis_type = Some(value),
        "port-id" => entry.port_id = Some(value),
        "port-id-type" => entry.port_type = Some(value),
        "system-name" => entry.system_name = Some(value),
        "port-description" => entry.port_description = Some(value),
        _ => {}
    }
}

fn apply_neighbor_state(entry: &mut NeighborBuilder, state: &serde_json::Value) {
    if let Some(v) = stripped_str(state, "chassis-id") {
        entry.chassis_id = Some(v);
    }
    if let Some(v) = stripped_str(state, "chassis-id-type") {
        entry.chassis_type = Some(v);
    }
    if let Some(v) = stripped_str(state, "port-id") {
        entry.port_id = Some(v);
    }
    if let Some(v) = stripped_str(state, "port-id-type") {
        entry.port_type = Some(v);
    }
    if let Some(v) = stripped_str(state, "system-name") {
        entry.system_name = Some(v);
    }
    if let Some(v) = stripped_str(state, "port-description") {
        entry.port_description = Some(v);
    }
}

fn joined_elems(prefix: Option<&Path>, path: Option<&Path>) -> Vec<PathElem> {
    let mut elems = Vec::new();
    if let Some(p) = prefix {
        elems.extend(p.elem.iter().cloned());
    }
    if let Some(p) = path {
        elems.extend(p.elem.iter().cloned());
    }
    elems
}

fn scalar_value(value: &TypedValue) -> Option<String> {
    use proto::gnmi::typed_value::Value;
    let rendered = match value.value.as_ref()? {
        Value::StringVal(s) | Value::AsciiVal(s) => s.clone(),
        Value::IntVal(i) => i.to_string(),
        Value::UintVal(u) => u.to_string(),
        _ => return None,
    };
    let trimmed = rendered.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn json_blob(value: &TypedValue) -> Option<serde_json::Value> {
    use proto::gnmi::typed_value::Value;
    let bytes = match value.value.as_ref()? {
        Value::JsonVal(bytes) | Value::JsonIetfVal(bytes) => bytes,
        _ => return None,
    };
    serde_json::from_slice(bytes).ok()
}

/// Reads the resolved key value of a keyed list element (`interface[name=…]`, `neighbor[id=…]`)
/// from a response path, skipping the request-side `*` wildcard.
fn elem_key(elems: &[PathElem], elem_name: &str, key_name: &str) -> Option<String> {
    elems
        .iter()
        .find(|e| strip_module(&e.name) == elem_name)
        .and_then(|e| e.key.get(key_name))
        .filter(|v| !v.is_empty() && v.as_str() != "*")
        .cloned()
}

fn strip_module(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn stripped_get<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    value
        .as_object()?
        .iter()
        .find(|(k, _)| strip_module(k) == key)
        .map(|(_, v)| v)
}

fn stripped_str(value: &serde_json::Value, key: &str) -> Option<String> {
    match stripped_get(value, key)? {
        serde_json::Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn descend_lldp_wrapper(json: &serde_json::Value) -> &serde_json::Value {
    if let Some(obj) = json.as_object() {
        if obj.len() == 1 {
            if let Some((k, v)) = obj.iter().next() {
                if strip_module(k) == "lldp" {
                    return v;
                }
            }
        }
    }
    json
}

fn enum_suffix(raw: &str) -> String {
    strip_module(raw).trim().to_ascii_uppercase()
}

// chassis-id-type identityref -> IEEE 802.1AB chassis subtype. A separate table from the port one:
// the shared `MAC_ADDRESS` name is chassis subtype 4 but port subtype 3, and the assembler only
// strips separators from a chassis when the subtype is 4.
fn chassis_subtype_from_type(raw: &str) -> u32 {
    match enum_suffix(raw).as_str() {
        "CHASSIS_COMPONENT" => 1,
        "INTERFACE_ALIAS" => 2,
        "PORT_COMPONENT" => 3,
        "MAC_ADDRESS" => CHASSIS_SUBTYPE_MAC,
        "NETWORK_ADDRESS" => CHASSIS_SUBTYPE_NETWORK_ADDRESS,
        "INTERFACE_NAME" => 6,
        "LOCAL" => 7,
        _ => 0,
    }
}

fn port_subtype_from_type(raw: &str) -> u32 {
    match enum_suffix(raw).as_str() {
        "INTERFACE_ALIAS" => 1,
        "PORT_COMPONENT" => 2,
        "MAC_ADDRESS" => PORT_SUBTYPE_MAC,
        "NETWORK_ADDRESS" => PORT_SUBTYPE_NETWORK_ADDRESS,
        "INTERFACE_NAME" => 5,
        "AGENT_CIRCUIT_ID" => 6,
        "LOCAL" => 7,
        _ => 0,
    }
}

fn canonical_chassis(subtype: u32, id: &str) -> String {
    match subtype {
        CHASSIS_SUBTYPE_MAC => canonical_mac_str(id),
        CHASSIS_SUBTYPE_NETWORK_ADDRESS => canonical_network_address(id),
        _ => id.trim().to_string(),
    }
}

fn canonical_port(subtype: u32, id: &str) -> String {
    match subtype {
        PORT_SUBTYPE_MAC => canonical_mac_str(id),
        PORT_SUBTYPE_NETWORK_ADDRESS => canonical_network_address(id),
        _ => id.trim().to_string(),
    }
}

fn canonical_network_address(raw: &str) -> String {
    match IpAddr::from_str(raw.trim()) {
        Ok(ip) => ip.to_string(),
        Err(_) => raw.trim().to_string(),
    }
}

/// Maps a gRPC `Status` returned after a completed connect to an outcome. A gRPC status is a
/// response — the device is provably a gNMI endpoint — so the device is kept (`reachable: true`)
/// with a kinded fault, never dropped as absence. An `Unauthenticated`/`PermissionDenied` status
/// with no credentials is an `AuthFailed` fault (the SNMP `DecodeFailed` precedent).
fn status_to_outcome(target_ip: IpAddr, status: &Status) -> ProbeOutcome {
    let kind = match status.code() {
        Code::Unauthenticated | Code::PermissionDenied => ProbeErrorKind::AuthFailed,
        _ => ProbeErrorKind::Other,
    };
    ProbeOutcome {
        lldp: None,
        gnmi_endpoint: None,
        kind: ProbeKind::Gnmi,
        target_ip,
        timestamp: SystemTime::now(),
        reachable: true,
        signals: Vec::new(),
        fault: Some(ProbeFault::new(
            kind,
            format!(
                "gnmi endpoint returned {:?}: {}",
                status.code(),
                status.message()
            ),
        )),
    }
}

fn assemble_outcome(target_ip: IpAddr, results: Vec<PortResult>) -> ProbeOutcome {
    let mut signals = Vec::new();
    let mut answered = false;
    let mut status: Option<Status> = None;
    let mut fault: Option<ProbeFault> = None;
    let mut lldp: Option<LldpObservation> = None;
    let mut gnmi_endpoint: Option<GnmiEndpoint> = None;

    for result in results {
        match result {
            PortResult::Answered(mut port_signals, port_lldp, endpoint) => {
                answered = true;
                signals.append(&mut port_signals);
                if lldp.is_none() {
                    lldp = port_lldp;
                }
                if gnmi_endpoint.is_none() {
                    gnmi_endpoint = Some(endpoint);
                }
            }
            PortResult::Status(gnmi_status) => {
                status.get_or_insert(gnmi_status);
            }
            PortResult::Fault(port_fault) => {
                fault = Some(port_fault);
            }
            PortResult::Absence => {}
        }
    }

    if answered {
        return ProbeOutcome {
            lldp,
            gnmi_endpoint,
            kind: ProbeKind::Gnmi,
            target_ip,
            timestamp: SystemTime::now(),
            reachable: true,
            signals,
            fault: None,
        };
    }

    if let Some(status) = status {
        return status_to_outcome(target_ip, &status);
    }

    ProbeOutcome {
        lldp: None,
        gnmi_endpoint: None,
        kind: ProbeKind::Gnmi,
        target_ip,
        timestamp: SystemTime::now(),
        reachable: false,
        signals: Vec::new(),
        fault,
    }
}

#[async_trait::async_trait]
impl Prober for GnmiProber {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Gnmi
    }

    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError> {
        let results = probe_ports(
            &self.ports,
            MAX_PORTS_IN_FLIGHT,
            ctx.port_budget.as_ref(),
            |port| {
                let ip = target.ip;
                async move { self.probe_port(ip, port, ctx).await }
            },
        )
        .await;

        Ok(assemble_outcome(target.ip, results))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use proto::gnmi::{Notification, Update};

    use crate::error::ConfigError;
    use crate::model::Target;

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 13));

    fn loopback_target(ip: Ipv4Addr) -> ResolvedTarget {
        let addr = IpAddr::V4(ip);
        ResolvedTarget {
            ip: addr,
            original: Target::Ip(addr),
            resolved_at: SystemTime::UNIX_EPOCH,
        }
    }

    fn ctx_with_timeout(ms: u64) -> ProbeCtx {
        ProbeCtx::new(Duration::from_millis(ms), 0)
    }

    fn prober() -> GnmiProber {
        GnmiProber::new(
            default_ports(),
            default_plaintext(),
            String::new(),
            Password::default(),
            default_get_paths(),
            default_lldp(),
        )
        .expect("valid")
    }

    #[test]
    fn new_rejects_empty_ports() {
        match GnmiProber::new(
            Vec::new(),
            false,
            String::new(),
            Password::default(),
            default_get_paths(),
            false,
        ) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("at least one port"), "got: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("empty ports must error"),
        }
    }

    #[test]
    fn new_dedups_and_sorts_ports() {
        let p = GnmiProber::new(
            vec![57400, 6030, 57400, 6030],
            false,
            String::new(),
            Password::default(),
            default_get_paths(),
            false,
        )
        .expect("valid");
        assert_eq!(p.ports(), &[6030, 57400]);
    }

    #[test]
    fn new_accepts_anonymous_defaults() {
        let p = prober();
        assert!(p.auth.is_none(), "no username means an anonymous probe");
        assert_eq!(p.get_paths.len(), 2);
    }

    #[test]
    fn new_accepts_valid_credentials() {
        let p = GnmiProber::new(
            default_ports(),
            false,
            "admin".to_string(),
            Password("NokiaSrl1!".to_string()),
            default_get_paths(),
            false,
        )
        .expect("valid");
        assert!(p.auth.is_some());
    }

    #[test]
    fn new_rejects_a_control_character_in_the_username() {
        match GnmiProber::new(
            default_ports(),
            false,
            "adm\u{0007}in".to_string(),
            Password::default(),
            default_get_paths(),
            false,
        ) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("username"), "got: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("a control character in the username must error at construction"),
        }
    }

    #[test]
    fn new_rejects_a_control_character_in_the_password() {
        match GnmiProber::new(
            default_ports(),
            false,
            "admin".to_string(),
            Password("pass\u{0007}word".to_string()),
            default_get_paths(),
            false,
        ) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("password"), "got: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("a control character in the password must error at construction"),
        }
    }

    #[test]
    fn defaults_match_the_gnmi_conventions() {
        assert_eq!(default_ports(), vec![57400]);
        assert!(!default_plaintext());
        assert_eq!(
            default_get_paths(),
            vec![
                "/system/state/hostname".to_string(),
                "/system/state/software-version".to_string(),
            ]
        );
    }

    #[test]
    fn probe_kind_returns_gnmi() {
        assert_eq!(prober().kind(), ProbeKind::Gnmi);
    }

    #[test]
    fn debug_redacts_credentials() {
        let p = GnmiProber::new(
            default_ports(),
            false,
            "admin".to_string(),
            Password("NokiaSrl1!".to_string()),
            default_get_paths(),
            false,
        )
        .expect("valid");
        let debug = format!("{p:?}");
        assert!(!debug.contains("NokiaSrl1!"), "password leaked: {debug}");
        assert!(!debug.contains("admin"), "username leaked: {debug}");
    }

    #[test]
    fn status_to_outcome_unauthenticated_keeps_the_device_as_auth_failure() {
        let outcome = status_to_outcome(TARGET, &Status::unauthenticated("no credentials"));
        assert!(
            outcome.reachable,
            "a gRPC status is a response — the device answered and must be kept"
        );
        assert!(outcome.signals.is_empty());
        let fault = outcome.fault.expect("auth failure is recorded");
        assert_eq!(fault.kind, ProbeErrorKind::AuthFailed);
    }

    #[test]
    fn status_to_outcome_permission_denied_is_auth_failure() {
        let outcome = status_to_outcome(TARGET, &Status::permission_denied("denied"));
        assert!(outcome.reachable);
        assert_eq!(
            outcome.fault.expect("fault recorded").kind,
            ProbeErrorKind::AuthFailed
        );
    }

    #[test]
    fn status_to_outcome_other_status_keeps_the_device_with_other_fault() {
        let outcome = status_to_outcome(TARGET, &Status::unimplemented("no Get"));
        assert!(
            outcome.reachable,
            "an endpoint that speaks gRPC is reachable even when the RPC is unimplemented"
        );
        assert_eq!(
            outcome.fault.expect("fault recorded").kind,
            ProbeErrorKind::Other
        );
    }

    #[test]
    fn collect_capability_signals_emits_version_model_and_encoding() {
        let response = CapabilityResponse {
            supported_models: vec![
                ModelData {
                    name: "openconfig-interfaces".to_string(),
                    organization: "OpenConfig".to_string(),
                    version: "3.0.0".to_string(),
                },
                ModelData {
                    name: "srl_nokia-system".to_string(),
                    ..Default::default()
                },
            ],
            supported_encodings: vec![Encoding::JsonIetf as i32, Encoding::Proto as i32],
            g_nmi_version: "0.10.0".to_string(),
            ..Default::default()
        };
        let mut signals = Vec::new();
        collect_capability_signals(response, &mut signals);
        assert!(signals.contains(&Signal::GnmiVersion("0.10.0".to_string())));
        assert!(signals.contains(&Signal::GnmiSupportedModel(
            "openconfig-interfaces 3.0.0 (OpenConfig)".to_string()
        )));
        assert!(signals.contains(&Signal::GnmiSupportedModel("srl_nokia-system".to_string())));
        assert!(signals.contains(&Signal::GnmiSupportedEncoding("JSON_IETF".to_string())));
        assert!(signals.contains(&Signal::GnmiSupportedEncoding("PROTO".to_string())));
    }

    #[test]
    fn collect_capability_signals_omits_an_empty_version() {
        let mut signals = Vec::new();
        collect_capability_signals(CapabilityResponse::default(), &mut signals);
        assert!(signals.is_empty());
    }

    #[test]
    fn collect_get_signals_emits_gnmi_state_from_an_update() {
        use proto::gnmi::typed_value::Value;
        let response = GetResponse {
            notification: vec![Notification {
                prefix: Some(parse_path("/system")),
                update: vec![Update {
                    path: Some(parse_path("/state/hostname")),
                    val: Some(TypedValue {
                        value: Some(Value::StringVal("srlinux-a".to_string())),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut signals = Vec::new();
        collect_get_signals(response, &mut signals);
        assert_eq!(
            signals,
            vec![Signal::GnmiState {
                path: "/system/state/hostname".to_string(),
                value: "srlinux-a".to_string(),
            }]
        );
    }

    #[test]
    fn render_typed_value_renders_scalars_and_skips_opaque_types() {
        use proto::gnmi::typed_value::Value;
        let string = TypedValue {
            value: Some(Value::StringVal("router-1".to_string())),
        };
        assert_eq!(render_typed_value(&string).as_deref(), Some("router-1"));
        let uint = TypedValue {
            value: Some(Value::UintVal(42)),
        };
        assert_eq!(render_typed_value(&uint).as_deref(), Some("42"));
        let boolean = TypedValue {
            value: Some(Value::BoolVal(true)),
        };
        assert_eq!(render_typed_value(&boolean).as_deref(), Some("true"));
        let bytes = TypedValue {
            value: Some(Value::BytesVal(vec![0x01, 0x02])),
        };
        assert!(render_typed_value(&bytes).is_none());
        let empty = TypedValue { value: None };
        assert!(render_typed_value(&empty).is_none());
    }

    #[test]
    fn parse_path_splits_on_slash_into_elements() {
        let path = parse_path("/system/state/hostname");
        let names: Vec<&str> = path.elem.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["system", "state", "hostname"]);
    }

    #[test]
    fn select_get_encoding_prefers_json_ietf_when_advertised() {
        let supported = vec![Encoding::JsonIetf as i32, Encoding::Proto as i32];
        assert_eq!(select_get_encoding(&supported), Encoding::JsonIetf as i32);
    }

    #[test]
    fn select_get_encoding_picks_json_when_only_json_advertised() {
        assert_eq!(
            select_get_encoding(&[Encoding::Json as i32]),
            Encoding::Json as i32
        );
    }

    #[test]
    fn select_get_encoding_picks_proto_when_only_proto_advertised() {
        assert_eq!(
            select_get_encoding(&[Encoding::Proto as i32]),
            Encoding::Proto as i32
        );
    }

    #[test]
    fn select_get_encoding_skips_unrenderable_bytes_for_the_next_renderable() {
        let supported = vec![Encoding::Bytes as i32, Encoding::Ascii as i32];
        assert_eq!(select_get_encoding(&supported), Encoding::Ascii as i32);
    }

    #[test]
    fn select_get_encoding_falls_back_when_only_unrenderable_advertised() {
        assert_eq!(
            select_get_encoding(&[Encoding::Bytes as i32]),
            Encoding::JsonIetf as i32
        );
    }

    #[test]
    fn select_get_encoding_falls_back_to_json_ietf_without_capabilities() {
        assert_eq!(select_get_encoding(&[]), Encoding::JsonIetf as i32);
        assert_ne!(select_get_encoding(&[]), Encoding::Json as i32);
    }

    #[test]
    fn parse_path_splits_origin_on_the_first_colon() {
        let path = parse_path("openconfig:/interfaces/interface");
        assert_eq!(path.origin, "openconfig");
        let names: Vec<&str> = path.elem.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["interfaces", "interface"]);
    }

    #[test]
    fn parse_path_accepts_a_hyphenated_origin() {
        let path = parse_path("srl_nokia-interfaces:/interface");
        assert_eq!(path.origin, "srl_nokia-interfaces");
        assert_eq!(path.elem.len(), 1);
        assert_eq!(path.elem[0].name, "interface");
    }

    #[test]
    fn parse_path_without_origin_has_empty_origin() {
        let path = parse_path("/system/state/hostname");
        assert!(path.origin.is_empty());
        let names: Vec<&str> = path.elem.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["system", "state", "hostname"]);
    }

    #[test]
    fn parse_path_parses_a_single_key() {
        let path = parse_path("/interfaces/interface[name=Ethernet1]");
        let elem = path.elem.last().expect("interface elem");
        assert_eq!(elem.name, "interface");
        assert_eq!(elem.key.get("name").map(String::as_str), Some("Ethernet1"));
    }

    #[test]
    fn parse_path_parses_multiple_keys() {
        let path = parse_path("/interface[name=et1][index=0]");
        let elem = &path.elem[0];
        assert_eq!(elem.name, "interface");
        assert_eq!(elem.key.get("name").map(String::as_str), Some("et1"));
        assert_eq!(elem.key.get("index").map(String::as_str), Some("0"));
    }

    #[test]
    fn parse_path_parses_a_wildcard_key() {
        let path = parse_path("/interface[name=*]");
        assert_eq!(path.elem[0].key.get("name").map(String::as_str), Some("*"));
    }

    #[test]
    fn parse_path_round_trips_a_keyed_path_through_append_path() {
        let original = parse_path("/interfaces/interface[name=et1][index=0]/state");
        let mut rendered = String::new();
        append_path(&mut rendered, &original);
        let reparsed = parse_path(&rendered);
        assert_eq!(original, reparsed);
        let mut rendered_again = String::new();
        append_path(&mut rendered_again, &reparsed);
        assert_eq!(rendered, rendered_again);
    }

    #[test]
    fn parse_path_degrades_unbalanced_brackets_to_a_literal_name() {
        let path = parse_path("/interface[name=et1");
        assert_eq!(path.elem.len(), 1);
        assert_eq!(path.elem[0].name, "interface[name=et1");
        assert!(path.elem[0].key.is_empty());
    }

    #[test]
    fn parse_path_never_panics_on_malformed_input() {
        for raw in [
            "[", "]", "a[b", "a]b", "a[=v]", "a[k=]", "::/", "a[[b]]", ":", "",
        ] {
            let _ = parse_path(raw);
        }
    }

    #[test]
    fn model_signal_includes_organization_when_present() {
        let model = ModelData {
            name: "openconfig-interfaces".to_string(),
            organization: "OpenConfig".to_string(),
            version: "3.0.0".to_string(),
        };
        assert_eq!(
            model_signal(&model),
            Some(Signal::GnmiSupportedModel(
                "openconfig-interfaces 3.0.0 (OpenConfig)".to_string()
            ))
        );
    }

    #[test]
    fn model_signal_omits_the_org_suffix_when_org_is_empty() {
        let model = ModelData {
            name: "srl_nokia-system".to_string(),
            organization: String::new(),
            version: "2024-03-31".to_string(),
        };
        assert_eq!(
            model_signal(&model),
            Some(Signal::GnmiSupportedModel(
                "srl_nokia-system 2024-03-31".to_string()
            ))
        );
    }

    #[test]
    fn model_signal_renders_org_without_version() {
        let model = ModelData {
            name: "arista-intf".to_string(),
            organization: "Arista".to_string(),
            version: String::new(),
        };
        assert_eq!(
            model_signal(&model),
            Some(Signal::GnmiSupportedModel(
                "arista-intf (Arista)".to_string()
            ))
        );
    }

    #[test]
    fn model_signal_returns_none_for_an_empty_name() {
        let model = ModelData {
            name: "   ".to_string(),
            organization: "OpenConfig".to_string(),
            version: "3.0.0".to_string(),
        };
        assert!(model_signal(&model).is_none());
    }

    #[test]
    fn render_typed_value_joins_a_leaf_list_of_scalars() {
        use proto::gnmi::typed_value::Value;
        let array = proto::gnmi::ScalarArray {
            element: vec![
                TypedValue {
                    value: Some(Value::StringVal("10.0.0.1".to_string())),
                },
                TypedValue {
                    value: Some(Value::UintVal(42)),
                },
            ],
        };
        let leaflist = TypedValue {
            value: Some(Value::LeaflistVal(array)),
        };
        assert_eq!(
            render_typed_value(&leaflist).as_deref(),
            Some("10.0.0.1,42")
        );
    }

    #[test]
    fn render_typed_value_skips_an_empty_leaf_list() {
        use proto::gnmi::typed_value::Value;
        let leaflist = TypedValue {
            value: Some(Value::LeaflistVal(proto::gnmi::ScalarArray::default())),
        };
        assert!(render_typed_value(&leaflist).is_none());
    }

    #[test]
    fn render_path_joins_prefix_and_path_with_sorted_keys() {
        let mut prefix = parse_path("/interfaces");
        let mut keyed = PathElem {
            name: "interface".to_string(),
            ..Default::default()
        };
        keyed
            .key
            .insert("name".to_string(), "ethernet-1/1".to_string());
        prefix.elem.push(keyed);
        let rendered = render_path(Some(&prefix), Some(&parse_path("/state/oper-status")));
        assert_eq!(
            rendered,
            "/interfaces/interface[name=ethernet-1/1]/state/oper-status"
        );
    }

    #[test]
    fn truncate_bounds_value_length_on_a_char_boundary() {
        let input = "€".repeat(120);
        assert_eq!(input.len(), 360);
        let out = truncate(&input);
        assert!(out.len() <= MAX_VALUE_BYTES);
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    #[test]
    fn assemble_prefers_signals_over_a_status() {
        let outcome = assemble_outcome(
            TARGET,
            vec![
                PortResult::Answered(
                    vec![Signal::GnmiVersion("0.10.0".to_string())],
                    None,
                    GnmiEndpoint {
                        port: 57400,
                        transport: Transport::Tls,
                        advertised_encodings: vec!["JSON_IETF".to_string()],
                    },
                ),
                PortResult::Status(Status::unauthenticated("no creds")),
            ],
        );
        assert!(outcome.reachable);
        assert!(outcome.fault.is_none(), "an answer outranks a status fault");
        assert_eq!(outcome.signals.len(), 1);
    }

    #[test]
    fn assemble_surfaces_the_answering_endpoint_not_a_default_guess() {
        let outcome = assemble_outcome(
            TARGET,
            vec![PortResult::Answered(
                vec![Signal::GnmiSupportedEncoding("JSON_IETF".to_string())],
                None,
                GnmiEndpoint {
                    port: 6030,
                    transport: Transport::Plaintext,
                    advertised_encodings: vec!["JSON_IETF".to_string(), "PROTO".to_string()],
                },
            )],
        );
        let endpoint = outcome
            .gnmi_endpoint
            .expect("an answered outcome surfaces the endpoint that answered");
        assert_eq!(endpoint.port, 6030);
        assert_eq!(endpoint.transport, Transport::Plaintext);
        assert_eq!(endpoint.advertised_encodings, vec!["JSON_IETF", "PROTO"]);
    }

    #[test]
    fn assemble_absence_and_status_carry_no_endpoint() {
        let absent = assemble_outcome(TARGET, vec![PortResult::Absence]);
        assert!(absent.gnmi_endpoint.is_none());
        let auth_failed = assemble_outcome(
            TARGET,
            vec![PortResult::Status(Status::unauthenticated("no creds"))],
        );
        assert!(
            auth_failed.gnmi_endpoint.is_none(),
            "an auth-failure answered nothing at the application layer, so no endpoint is surfaced"
        );
    }

    #[test]
    fn assemble_maps_an_unauthenticated_status_to_reachable_auth_failure() {
        let outcome = assemble_outcome(
            TARGET,
            vec![PortResult::Status(Status::unauthenticated("no creds"))],
        );
        assert!(outcome.reachable);
        assert_eq!(
            outcome.fault.expect("fault recorded").kind,
            ProbeErrorKind::AuthFailed
        );
    }

    #[test]
    fn assemble_maps_absence_when_nothing_answered() {
        let outcome = assemble_outcome(TARGET, vec![PortResult::Absence, PortResult::Absence]);
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        assert!(outcome.fault.is_none());
    }

    #[test]
    fn assemble_surfaces_a_connect_fault_when_nothing_answered() {
        let outcome = assemble_outcome(
            TARGET,
            vec![PortResult::Fault(ProbeFault::new(
                ProbeErrorKind::PermissionDenied,
                "gnmi connect denied on port 57400",
            ))],
        );
        assert!(!outcome.reachable);
        assert_eq!(
            outcome.fault.expect("fault recorded").kind,
            ProbeErrorKind::PermissionDenied
        );
    }

    #[test]
    fn gnmi_prober_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<GnmiProber>();
        assert_send_sync::<Box<dyn Prober>>();
    }

    #[tokio::test]
    async fn probe_reports_absence_for_a_closed_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let p = GnmiProber::new(
            vec![port],
            true,
            String::new(),
            Password::default(),
            Vec::new(),
            false,
        )
        .expect("valid");
        let outcome = p
            .probe(
                &loopback_target(Ipv4Addr::LOCALHOST),
                &ctx_with_timeout(500),
            )
            .await
            .expect("a refused endpoint is an outcome, not an error");
        assert_eq!(outcome.kind, ProbeKind::Gnmi);
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        assert!(outcome.fault.is_none());
    }

    // tonic's opaque transport error exposes the connector's io::Error through `source()`, so a
    // refused connect classifies as absence, not a blanket fault. Goes red if a future tonic
    // release stops threading the errno.
    #[tokio::test]
    async fn a_refused_connect_exposes_econnrefused_and_is_absence() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let endpoint = Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
            .expect("uri")
            .connect_timeout(Duration::from_millis(500));
        let err = endpoint
            .connect()
            .await
            .expect_err("a connect to a closed port fails");
        let io = classify::io_error_in_chain(&err)
            .expect("tonic must expose the connector io error in its source chain");
        assert_eq!(io.kind(), std::io::ErrorKind::ConnectionRefused);
        assert!(
            matches!(classify_connect_error(port, &err), ConnectError::Absence),
            "a refused connect must be absence"
        );
    }

    fn string_val(value: &str) -> Option<TypedValue> {
        use proto::gnmi::typed_value::Value;
        Some(TypedValue {
            value: Some(Value::StringVal(value.to_string())),
        })
    }

    fn plain_elem(name: &str) -> PathElem {
        PathElem {
            name: name.to_string(),
            ..Default::default()
        }
    }

    fn keyed_elem(name: &str, key: &str, value: &str) -> PathElem {
        let mut map = HashMap::new();
        map.insert(key.to_string(), value.to_string());
        PathElem {
            name: name.to_string(),
            key: map,
        }
    }

    // Response elements arrive as structured `PathElem`s with keys intact — including interface
    // names that contain `/` (SR Linux `ethernet-1/1`), which a request-path string cannot express.
    fn local_update(leaf: &str, value: &str) -> Update {
        Update {
            path: Some(Path {
                elem: vec![plain_elem("lldp"), plain_elem("state"), plain_elem(leaf)],
                ..Default::default()
            }),
            val: string_val(value),
            ..Default::default()
        }
    }

    fn neighbor_update(interface: &str, id: &str, leaf: &str, value: &str) -> Update {
        Update {
            path: Some(Path {
                elem: vec![
                    plain_elem("lldp"),
                    plain_elem("interfaces"),
                    keyed_elem("interface", "name", interface),
                    plain_elem("neighbors"),
                    keyed_elem("neighbor", "id", id),
                    plain_elem("state"),
                    plain_elem(leaf),
                ],
                ..Default::default()
            }),
            val: string_val(value),
            ..Default::default()
        }
    }

    fn lldp_leaf_response(updates: Vec<Update>) -> GetResponse {
        GetResponse {
            notification: vec![Notification {
                update: updates,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn device_b_leaf_response() -> GetResponse {
        // Device B renders MACs Cisco-dotted; the parser must canonicalize to bare hex so B's
        // endpoints reconcile with the SNMP end's stored form.
        lldp_leaf_response(vec![
            local_update("chassis-id", "bbbb.bbbb.bbbb"),
            local_update("chassis-id-type", "openconfig-lldp-types:MAC_ADDRESS"),
            neighbor_update("ethernet-1/1", "0", "chassis-id", "aaaa.aaaa.aaaa"),
            neighbor_update(
                "ethernet-1/1",
                "0",
                "chassis-id-type",
                "openconfig-lldp-types:MAC_ADDRESS",
            ),
            neighbor_update("ethernet-1/1", "0", "port-id", "ethernet-1/5"),
            neighbor_update(
                "ethernet-1/1",
                "0",
                "port-id-type",
                "openconfig-lldp-types:INTERFACE_NAME",
            ),
            neighbor_update("ethernet-1/1", "0", "system-name", "device-a"),
        ])
    }

    #[test]
    fn default_lldp_is_off() {
        assert!(!default_lldp());
    }

    #[test]
    fn chassis_subtype_table_maps_every_openconfig_type() {
        assert_eq!(chassis_subtype_from_type("CHASSIS_COMPONENT"), 1);
        assert_eq!(chassis_subtype_from_type("INTERFACE_ALIAS"), 2);
        assert_eq!(chassis_subtype_from_type("PORT_COMPONENT"), 3);
        assert_eq!(chassis_subtype_from_type("MAC_ADDRESS"), 4);
        assert_eq!(chassis_subtype_from_type("NETWORK_ADDRESS"), 5);
        assert_eq!(chassis_subtype_from_type("INTERFACE_NAME"), 6);
        assert_eq!(chassis_subtype_from_type("LOCAL"), 7);
        assert_eq!(chassis_subtype_from_type("SOMETHING_ELSE"), 0);
    }

    #[test]
    fn port_subtype_table_maps_every_openconfig_type() {
        assert_eq!(port_subtype_from_type("INTERFACE_ALIAS"), 1);
        assert_eq!(port_subtype_from_type("PORT_COMPONENT"), 2);
        assert_eq!(port_subtype_from_type("MAC_ADDRESS"), 3);
        assert_eq!(port_subtype_from_type("NETWORK_ADDRESS"), 4);
        assert_eq!(port_subtype_from_type("INTERFACE_NAME"), 5);
        assert_eq!(port_subtype_from_type("AGENT_CIRCUIT_ID"), 6);
        assert_eq!(port_subtype_from_type("LOCAL"), 7);
        assert_eq!(port_subtype_from_type("SOMETHING_ELSE"), 0);
    }

    #[test]
    fn mac_address_maps_to_distinct_chassis_and_port_subtypes() {
        assert_eq!(chassis_subtype_from_type("MAC_ADDRESS"), 4);
        assert_eq!(port_subtype_from_type("MAC_ADDRESS"), 3);
    }

    #[test]
    fn subtype_tables_strip_the_module_prefix_and_ignore_case() {
        assert_eq!(
            chassis_subtype_from_type("openconfig-lldp-types:MAC_ADDRESS"),
            4
        );
        assert_eq!(
            port_subtype_from_type("openconfig-lldp-types:mac_address"),
            3
        );
    }

    #[test]
    fn canonical_chassis_renders_network_address_as_canonical_ip() {
        assert_eq!(canonical_chassis(5, "10.0.0.9"), "10.0.0.9");
        assert_eq!(canonical_chassis(5, " 10.0.0.9 "), "10.0.0.9");
        assert_eq!(
            canonical_chassis(5, "2001:0DB8:0000:0000:0000:0000:0000:0001"),
            "2001:db8::1"
        );
        assert_eq!(canonical_chassis(5, "not-an-ip"), "not-an-ip");
    }

    #[test]
    fn parse_lldp_leaf_updates_group_by_interface_and_neighbor_id() {
        let obs = parse_lldp_response(device_b_leaf_response());
        assert_eq!(obs.discovered_via, "gnmi");
        assert_eq!(obs.local_chassis_id, "bbbbbbbbbbbb");
        assert_eq!(obs.local_chassis_subtype, 4);
        assert_eq!(obs.neighbors.len(), 1);
        let n = &obs.neighbors[0];
        assert_eq!(n.local_port, "ethernet-1/1");
        assert_eq!(n.remote_chassis_id, "aaaaaaaaaaaa");
        assert_eq!(n.remote_chassis_subtype, 4);
        assert_eq!(n.remote_port_id, "ethernet-1/5");
        assert_eq!(n.remote_port_subtype, 5);
        assert_eq!(n.remote_sys_name.as_deref(), Some("device-a"));
    }

    #[test]
    fn parse_lldp_groups_two_neighbors_on_separate_interfaces() {
        let obs = parse_lldp_response(lldp_leaf_response(vec![
            neighbor_update("eth1", "0", "chassis-id", "aa:aa:aa:aa:aa:aa"),
            neighbor_update("eth1", "0", "chassis-id-type", "MAC_ADDRESS"),
            neighbor_update("eth2", "0", "chassis-id", "bb:bb:bb:bb:bb:bb"),
            neighbor_update("eth2", "0", "chassis-id-type", "MAC_ADDRESS"),
        ]));
        assert_eq!(obs.neighbors.len(), 2);
        assert_eq!(obs.neighbors[0].local_port, "eth1");
        assert_eq!(obs.neighbors[0].remote_chassis_id, "aaaaaaaaaaaa");
        assert_eq!(obs.neighbors[1].local_port, "eth2");
        assert_eq!(obs.neighbors[1].remote_chassis_id, "bbbbbbbbbbbb");
    }

    #[test]
    fn parse_lldp_json_ietf_subtree_blob() {
        use proto::gnmi::typed_value::Value;
        let blob = serde_json::json!({
            "openconfig-lldp:lldp": {
                "state": {
                    "chassis-id": "bb:bb:bb:bb:bb:bb",
                    "chassis-id-type": "openconfig-lldp-types:MAC_ADDRESS"
                },
                "interfaces": {
                    "interface": [{
                        "name": "ethernet-1/1",
                        "neighbors": {
                            "neighbor": [{
                                "id": "0",
                                "state": {
                                    "chassis-id": "0011.2233.4455",
                                    "chassis-id-type": "openconfig-lldp-types:MAC_ADDRESS",
                                    "port-id": "ethernet-2/1",
                                    "port-id-type": "openconfig-lldp-types:INTERFACE_NAME",
                                    "system-name": "peer-a",
                                    "port-description": "uplink"
                                }
                            }]
                        }
                    }]
                }
            }
        });
        let response = GetResponse {
            notification: vec![Notification {
                prefix: Some(parse_path("/lldp")),
                update: vec![Update {
                    path: None,
                    val: Some(TypedValue {
                        value: Some(Value::JsonIetfVal(serde_json::to_vec(&blob).expect("json"))),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let obs = parse_lldp_response(response);
        assert_eq!(obs.discovered_via, "gnmi");
        assert_eq!(obs.local_chassis_id, "bbbbbbbbbbbb");
        assert_eq!(obs.local_chassis_subtype, 4);
        assert_eq!(obs.neighbors.len(), 1);
        let n = &obs.neighbors[0];
        assert_eq!(n.local_port, "ethernet-1/1");
        assert_eq!(n.remote_chassis_id, "001122334455");
        assert_eq!(n.remote_chassis_subtype, 4);
        assert_eq!(n.remote_port_id, "ethernet-2/1");
        assert_eq!(n.remote_port_subtype, 5);
        assert_eq!(n.remote_sys_name.as_deref(), Some("peer-a"));
        assert_eq!(n.remote_port_desc.as_deref(), Some("uplink"));
    }

    #[test]
    fn parse_lldp_empty_subtree_is_reachable_with_no_neighbors() {
        let obs = parse_lldp_response(GetResponse::default());
        assert_eq!(obs.discovered_via, "gnmi");
        assert!(obs.local_chassis_id.is_empty());
        assert!(obs.neighbors.is_empty());
    }

    fn hostname_state_response() -> GetResponse {
        use proto::gnmi::typed_value::Value;
        GetResponse {
            notification: vec![Notification {
                update: vec![Update {
                    path: Some(parse_path("/system/state/hostname")),
                    val: Some(TypedValue {
                        value: Some(Value::StringVal("srlinux-a".to_string())),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn lldp_get_error_does_not_clobber_a_successful_state_get() {
        let mut acc = PortAccumulator::default();
        acc.record_get(Ok(hostname_state_response()), GetHandler::State);
        acc.record_get(Err(Status::unimplemented("no lldp path")), GetHandler::Lldp);
        match acc.into_result(57400, Transport::Tls) {
            PortResult::Answered(signals, lldp, endpoint) => {
                assert!(!signals.is_empty(), "state signals survive the lldp error");
                assert!(lldp.is_none(), "a failed lldp Get leaves no observation");
                assert_eq!(endpoint.port, 57400);
                assert_eq!(endpoint.transport, Transport::Tls);
            }
            _ => panic!("a successful state Get must answer"),
        }
    }

    #[test]
    fn state_get_error_does_not_clobber_a_successful_lldp_get() {
        let mut acc = PortAccumulator::default();
        acc.record_get(
            Err(Status::unimplemented("no state path")),
            GetHandler::State,
        );
        acc.record_get(Ok(device_b_leaf_response()), GetHandler::Lldp);
        match acc.into_result(6030, Transport::Plaintext) {
            PortResult::Answered(signals, lldp, endpoint) => {
                assert!(
                    signals.is_empty(),
                    "no state signals, but the port still answered"
                );
                assert!(
                    lldp.is_some(),
                    "the lldp observation survives the state error"
                );
                assert_eq!(endpoint.port, 6030);
                assert_eq!(endpoint.transport, Transport::Plaintext);
            }
            _ => panic!("a successful lldp Get must answer"),
        }
    }

    fn sourced_outcome(ip: Ipv4Addr, lldp: LldpObservation) -> ProbeOutcome {
        ProbeOutcome {
            kind: ProbeKind::Gnmi,
            target_ip: IpAddr::V4(ip),
            timestamp: SystemTime::UNIX_EPOCH,
            reachable: true,
            signals: Vec::new(),
            fault: None,
            lldp: Some(lldp),
            gnmi_endpoint: None,
        }
    }

    // Deleting `canonical_mac_str` from `canonical_chassis` OR the `MAC_ADDRESS`→4 chassis mapping
    // makes B's dotted MACs no longer match the SNMP end's bare hex: the edge key diverges and the
    // link count becomes 2 — this assertion goes red.
    #[test]
    fn cross_source_snmp_and_gnmi_collapse_to_one_link_with_merged_source() {
        use crate::model::scan::ScanMetadata;
        use crate::topology::TopologyAssembler;

        let snmp_a = LldpObservation {
            local_chassis_id: "aaaaaaaaaaaa".to_string(),
            local_chassis_subtype: 4,
            neighbors: vec![LldpNeighbor {
                local_port: "Ethernet1/7".to_string(),
                remote_chassis_id: "bbbbbbbbbbbb".to_string(),
                remote_chassis_subtype: 4,
                remote_port_id: "ethernet-1/1".to_string(),
                remote_port_subtype: 5,
                remote_port_desc: None,
                remote_sys_name: Some("device-b".to_string()),
            }],
            discovered_via: "lldp".to_string(),
        };

        let gnmi_b = parse_lldp_response(device_b_leaf_response());
        assert_eq!(gnmi_b.local_chassis_id, "bbbbbbbbbbbb");
        assert_eq!(gnmi_b.discovered_via, "gnmi");

        let mut assembler = TopologyAssembler::new(Arc::new(ScanMetadata::default()));
        assembler.observe_outcomes(&[sourced_outcome(Ipv4Addr::new(10, 0, 0, 1), snmp_a)]);
        assembler.observe_outcomes(&[sourced_outcome(Ipv4Addr::new(10, 0, 0, 2), gnmi_b)]);
        let links = assembler.finish();

        assert_eq!(links.len(), 1, "one physical link across both sources");
        let link = &links[0];
        assert_eq!(link.a.chassis_id, "aaaaaaaaaaaa");
        assert_eq!(link.b.chassis_id, "bbbbbbbbbbbb");
        assert_eq!(link.discovered_via, "gnmi,lldp");
    }
}
