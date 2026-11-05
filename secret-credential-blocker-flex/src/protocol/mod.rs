// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Traffic classification: which protocol a request speaks, which operation
//! it invokes, and which parts of its body are scanned.

pub mod a2a;
pub mod jsonrpc;
pub mod mcp;
pub mod multipart;
pub mod query;

use serde_json::Value;

use jsonrpc::Envelope;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Rest,
    /// JSON-RPC with a method that is neither MCP nor A2A.
    JsonRpc,
    Mcp,
    A2aLegacy,
    A2aV1JsonRpc,
    A2aV1Http,
}

impl Protocol {
    pub fn label(self) -> &'static str {
        match self {
            Protocol::Rest => "rest",
            Protocol::JsonRpc => "jsonrpc",
            Protocol::Mcp => "mcp",
            Protocol::A2aLegacy => "a2a-0.3",
            Protocol::A2aV1JsonRpc => "a2a-1.0-jsonrpc",
            Protocol::A2aV1Http => "a2a-1.0-http",
        }
    }

    pub fn is_jsonrpc(self) -> bool {
        matches!(self, Protocol::JsonRpc | Protocol::Mcp | Protocol::A2aLegacy | Protocol::A2aV1JsonRpc)
    }
}

/// The `protocol` setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Auto,
    Rest,
    Mcp,
    A2a,
}

/// Request facts known at the headers stage.
#[derive(Debug, Clone)]
pub struct RequestMeta {
    pub method: String,
    /// Path without the query string.
    pub path: String,
    /// Lowercased `content-type`, empty when absent.
    pub content_type: String,
    pub is_v1: bool,
}

impl RequestMeta {
    pub fn is_grpc(&self) -> bool {
        self.content_type.starts_with("application/grpc")
    }

    fn mime(&self) -> &str {
        self.content_type.split(';').next().unwrap_or("").trim()
    }

    fn is_json(&self) -> bool {
        let m = self.mime();
        m.is_empty() || m.ends_with("/json") || m.ends_with("+json")
    }
}

/// What the body stage does with the body.
#[derive(Debug, Clone, PartialEq)]
pub enum BodyPlan {
    /// Walk the parsed JSON under each root (empty root = whole document).
    Json { roots: Vec<Vec<&'static str>>, push_config: bool },
    Form,
    Multipart(String),
    Text,
    /// Nothing to scan.
    Skip,
}

#[derive(Debug, Clone)]
pub struct Classified {
    pub protocol: Protocol,
    pub op: Option<String>,
    /// JSON-RPC `id` (`Some(Value::Null)` for a batch or unknown id).
    pub id: Option<Value>,
    pub doc: Option<Value>,
    pub plan: BodyPlan,
}

/// Classification from headers alone: used for bodyless requests and for
/// header/query findings that are blocked before the body arrives.
pub fn provisional(mode: Mode, meta: &RequestMeta) -> (Protocol, Option<&'static str>) {
    if mode != Mode::Rest && mode != Mode::Mcp {
        if let Some(op) = a2a::http_json_operation(&meta.method, &meta.path) {
            // `message:send`, `tasks/{id}:cancel` are unambiguous even without the version header.
            let custom_verb = meta.path.rsplit('/').next().is_some_and(|s| s.contains(':'));
            if meta.is_v1 || mode == Mode::A2a || custom_verb {
                return (Protocol::A2aV1Http, Some(op));
            }
        }
        if meta.is_v1 && meta.method != "POST" {
            return (Protocol::A2aV1Http, None);
        }
    }
    (Protocol::Rest, None)
}

/// Full classification once the body is available.
pub fn classify(mode: Mode, meta: &RequestMeta, body: &[u8], rest_body: bool, multipart_on: bool) -> Classified {
    let (prov, prov_op) = provisional(mode, meta);
    let mut out = Classified {
        protocol: prov,
        op: prov_op.map(str::to_string),
        id: None,
        doc: None,
        plan: BodyPlan::Skip,
    };
    if body.iter().all(u8::is_ascii_whitespace) {
        return out;
    }
    if multipart::is_multipart(&meta.content_type) {
        if multipart_on && rest_body {
            if let Some(b) = multipart::boundary(&meta.content_type) {
                out.plan = BodyPlan::Multipart(b);
            }
        }
        return out;
    }
    if meta.mime() == "application/x-www-form-urlencoded" {
        if rest_body {
            out.plan = BodyPlan::Form;
        }
        return out;
    }
    if !meta.is_json() {
        if rest_body && (meta.mime().starts_with("text/") || meta.mime().ends_with("+xml") || meta.mime().ends_with("/xml")) {
            out.plan = BodyPlan::Text;
        }
        return out;
    }
    let Ok(doc) = serde_json::from_slice::<Value>(body) else {
        // Unparseable "JSON": treat as text so a pasted secret is still found.
        if rest_body {
            out.plan = BodyPlan::Text;
        }
        return out;
    };
    let envelope = if mode == Mode::Rest { Envelope::NotJsonRpc } else { jsonrpc::envelope(&doc) };
    match envelope {
        Envelope::Single { method, id } => {
            let (protocol, roots, push_config) = jsonrpc_plan(mode, meta.is_v1, &method);
            out.protocol = protocol;
            out.op = Some(method);
            out.id = Some(id.unwrap_or(Value::Null));
            out.plan = match roots {
                Some(roots) => BodyPlan::Json { roots, push_config },
                None => BodyPlan::Skip,
            };
        }
        Envelope::Batch => {
            out.protocol = if mode == Mode::A2a { Protocol::A2aLegacy } else { Protocol::Mcp };
            out.id = Some(Value::Null);
            out.plan = BodyPlan::Json { roots: vec![vec![]], push_config: false };
        }
        Envelope::NotJsonRpc if out.protocol == Protocol::A2aV1Http || (meta.is_v1 && meta.method == "POST" && mode != Mode::Rest && mode != Mode::Mcp) => {
            out.protocol = Protocol::A2aV1Http;
            let push = out.op.as_deref().is_some_and(a2a::is_push_config_write);
            out.plan = BodyPlan::Json { roots: vec![vec![]], push_config: push };
        }
        Envelope::NotJsonRpc => {
            if rest_body {
                out.plan = BodyPlan::Json { roots: vec![vec![]], push_config: false };
            }
        }
    }
    out.doc = Some(doc);
    out
}

/// `(protocol, scan roots or None for pass-through, push-config write?)`.
fn jsonrpc_plan(mode: Mode, is_v1: bool, method: &str) -> (Protocol, Option<Vec<Vec<&'static str>>>, bool) {
    let as_a2a = mode == Mode::A2a || (mode == Mode::Auto && a2a::is_a2a_method(method));
    let as_mcp = mode == Mode::Mcp || (mode == Mode::Auto && !as_a2a && mcp::is_mcp_method(method));
    if as_a2a {
        let protocol = if is_v1 || a2a::is_v1_method(method) { Protocol::A2aV1JsonRpc } else { Protocol::A2aLegacy };
        return (protocol, Some(vec![vec!["params"]]), a2a::is_push_config_write(method));
    }
    if as_mcp {
        let roots = match method {
            mcp::TOOLS_CALL | "prompts/get" => Some(vec![vec!["params", "arguments"]]),
            "resources/read" => Some(vec![vec!["params", "uri"]]),
            "completion/complete" => Some(vec![vec!["params", "argument"]]),
            m if m.starts_with("notifications/") || !mcp::carries_content(m) => None,
            _ => Some(vec![vec!["params"]]),
        };
        return (Protocol::Mcp, roots, false);
    }
    (Protocol::JsonRpc, Some(vec![vec!["params"]]), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn meta(method: &str, path: &str, ct: &str, is_v1: bool) -> RequestMeta {
        RequestMeta { method: method.into(), path: path.into(), content_type: ct.into(), is_v1 }
    }

    fn body(v: Value) -> Vec<u8> {
        serde_json::to_vec(&v).unwrap()
    }

    #[test]
    fn mcp_tools_call() {
        let b = body(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"x","arguments":{}}}));
        let c = classify(Mode::Auto, &meta("POST", "/mcp", "application/json", false), &b, true, true);
        assert_eq!(c.protocol, Protocol::Mcp);
        assert_eq!(c.id, Some(json!(3)));
        assert_eq!(c.plan, BodyPlan::Json { roots: vec![vec!["params", "arguments"]], push_config: false });
    }

    #[test]
    fn mcp_notifications_and_listings_pass() {
        for m in ["notifications/initialized", "tools/list", "initialize"] {
            let b = body(json!({"jsonrpc":"2.0","method":m,"id":1}));
            let c = classify(Mode::Auto, &meta("POST", "/mcp", "application/json", false), &b, true, true);
            assert_eq!(c.plan, BodyPlan::Skip, "{m}");
        }
    }

    #[test]
    fn a2a_versions() {
        let m = meta("POST", "/", "application/json", false);
        let b = body(json!({"jsonrpc":"2.0","id":"a","method":"message/send","params":{}}));
        assert_eq!(classify(Mode::Auto, &m, &b, true, true).protocol, Protocol::A2aLegacy);
        let b = body(json!({"jsonrpc":"2.0","id":"a","method":"SendMessage","params":{}}));
        assert_eq!(classify(Mode::Auto, &m, &b, true, true).protocol, Protocol::A2aV1JsonRpc);
        let b = body(json!({"jsonrpc":"2.0","id":"a","method":"message/send","params":{}}));
        let v1 = meta("POST", "/", "application/json", true);
        assert_eq!(classify(Mode::Auto, &v1, &b, true, true).protocol, Protocol::A2aV1JsonRpc);
        let b = body(json!({"jsonrpc":"2.0","id":1,"method":"tasks/pushNotificationConfig/set","params":{}}));
        assert!(matches!(classify(Mode::Auto, &m, &b, true, true).plan, BodyPlan::Json { push_config: true, .. }));
    }

    #[test]
    fn a2a_http_json() {
        let b = body(json!({"message":{"parts":[{"text":"hi"}]}}));
        let c = classify(Mode::Auto, &meta("POST", "/acme/message:send", "application/json", true), &b, true, true);
        assert_eq!(c.protocol, Protocol::A2aV1Http);
        assert_eq!(c.op.as_deref(), Some("SendMessage"));
        let c = classify(Mode::Auto, &meta("POST", "/whatever", "application/json", true), &b, true, true);
        assert_eq!(c.protocol, Protocol::A2aV1Http);
        assert_eq!(provisional(Mode::Auto, &meta("GET", "/tasks/t1", "", true)), (Protocol::A2aV1Http, Some("GetTask")));
        assert_eq!(provisional(Mode::Auto, &meta("GET", "/tasks/t1", "", false)).0, Protocol::Rest);
        assert_eq!(provisional(Mode::Rest, &meta("POST", "/message:send", "", true)).0, Protocol::Rest);
    }

    #[test]
    fn rest_bodies() {
        let m = meta("POST", "/orders", "application/json; charset=utf-8", false);
        let c = classify(Mode::Auto, &m, b"{\"a\":1}", true, true);
        assert_eq!((c.protocol, c.plan), (Protocol::Rest, BodyPlan::Json { roots: vec![vec![]], push_config: false }));
        assert_eq!(classify(Mode::Auto, &m, b"{\"a\":1}", false, true).plan, BodyPlan::Skip);
        let f = meta("POST", "/", "application/x-www-form-urlencoded", false);
        assert_eq!(classify(Mode::Auto, &f, b"a=b", true, true).plan, BodyPlan::Form);
        let mp = meta("POST", "/", "multipart/form-data; boundary=x", false);
        assert_eq!(classify(Mode::Auto, &mp, b"--x", true, true).plan, BodyPlan::Multipart("x".into()));
        assert_eq!(classify(Mode::Auto, &mp, b"--x", true, false).plan, BodyPlan::Skip);
        let bin = meta("POST", "/", "application/octet-stream", false);
        assert_eq!(classify(Mode::Auto, &bin, b"\x00\x01", true, true).plan, BodyPlan::Skip);
        assert_eq!(classify(Mode::Auto, &m, b"{not json", true, true).plan, BodyPlan::Text);
    }

    #[test]
    fn forced_rest_ignores_envelopes() {
        let b = body(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}));
        let c = classify(Mode::Rest, &meta("POST", "/mcp", "application/json", false), &b, true, true);
        assert_eq!(c.protocol, Protocol::Rest);
    }
}
