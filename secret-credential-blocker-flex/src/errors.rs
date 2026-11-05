// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Protocol-native error bodies for blocked requests and responses.
//!
//! Client-facing errors carry at most the detector kinds and locations —
//! never a value and never a fingerprint. `errorDetail: false` drops both.

use serde_json::{json, Map, Value};

use crate::protocol::llm::Dialect;
use crate::protocol::Protocol;
use crate::walk::Hit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Secret,
    Unscannable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Request,
    Response,
}

pub struct Detail<'a> {
    pub hits: &'a [Hit],
    pub show: bool,
    pub domain: &'a str,
}

#[derive(Debug, PartialEq)]
pub struct Reply {
    pub status: u32,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

const ERROR_INFO: &str = "type.googleapis.com/google.rpc.ErrorInfo";
const PROBLEM_BASE: &str = "https://docs.p4a.ai/problems/";

fn reason_code(reason: Reason, dir: Direction) -> &'static str {
    match (reason, dir) {
        (Reason::Secret, Direction::Request) => "SECRET_DETECTED",
        (Reason::Secret, Direction::Response) => "SECRET_DETECTED_IN_RESPONSE",
        (Reason::Unscannable, _) => "PAYLOAD_UNSCANNABLE",
    }
}

fn message(reason: Reason, dir: Direction) -> &'static str {
    match (reason, dir) {
        (Reason::Secret, Direction::Request) => "Request blocked: it contains a secret or credential",
        (Reason::Secret, Direction::Response) => "Response withheld: it contains a secret or credential",
        (Reason::Unscannable, Direction::Request) => "Request blocked: the payload could not be scanned for secrets",
        (Reason::Unscannable, Direction::Response) => "Response withheld: the payload could not be scanned for secrets",
    }
}

fn unique<'a>(it: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for s in it {
        if !v.iter().any(|x| x == s) {
            v.push(s.to_string());
        }
    }
    v
}

impl Detail<'_> {
    fn detectors(&self) -> Vec<String> {
        unique(self.hits.iter().map(|h| h.kind.as_str()))
    }

    fn paths(&self) -> Vec<String> {
        unique(self.hits.iter().map(|h| h.location.as_str()))
    }

    fn summary(&self) -> String {
        if !self.show || self.hits.is_empty() {
            return String::new();
        }
        format!(" ({} at {})", self.detectors().join(", "), self.paths().join(", "))
    }

    fn error_info(&self, reason: &str) -> Value {
        let mut metadata = Map::new();
        if self.show && !self.hits.is_empty() {
            metadata.insert("detectors".into(), Value::String(self.detectors().join(",")));
            metadata.insert("paths".into(), Value::String(self.paths().join(",")));
        }
        json!({"@type": ERROR_INFO, "reason": reason, "domain": self.domain, "metadata": metadata})
    }
}

fn jsonrpc_error(id: &Value, code: i64, message: String, data: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message, "data": data}})
}

/// The error body for `protocol`. For requests `status` is the HTTP status to
/// send; for responses the caller keeps the upstream status and uses `body`.
pub fn build(
    protocol: Protocol,
    op: Option<&str>,
    id: Option<&Value>,
    dir: Direction,
    reason: Reason,
    detail: &Detail,
) -> Reply {
    let null = Value::Null;
    let id = id.unwrap_or(&null);
    let code = reason_code(reason, dir);
    let msg = message(reason, dir);
    let (status, ct, body) = match protocol {
        Protocol::Rest => {
            let status = match (dir, reason) {
                (Direction::Request, Reason::Secret) => 400,
                (Direction::Request, Reason::Unscannable) => 413,
                (Direction::Response, _) => 502,
            };
            let mut p = json!({
                "type": format!("{PROBLEM_BASE}{}", code.to_ascii_lowercase().replace('_', "-")),
                "title": msg,
                "status": status,
                "detail": format!("{msg}{}", detail.summary()),
            });
            if detail.show && !detail.hits.is_empty() {
                p["findings"] = Value::Array(
                    detail.hits.iter().map(|h| json!({"type": h.kind, "location": h.location})).collect(),
                );
            }
            (status, "application/problem+json", p)
        }
        Protocol::Mcp | Protocol::JsonRpc => {
            if dir == Direction::Response && op == Some(crate::protocol::mcp::TOOLS_CALL) {
                let text = format!("{msg}{}.", detail.summary());
                let v = json!({"jsonrpc": "2.0", "id": id, "result": {"isError": true, "content": [{"type": "text", "text": text}]}});
                (200, "application/json", v)
            } else {
                let mut data = json!({"reason": code});
                if detail.show && !detail.hits.is_empty() {
                    data["detectors"] = json!(detail.detectors());
                    data["paths"] = json!(detail.paths());
                }
                (200, "application/json", jsonrpc_error(id, rpc_code(dir, reason), msg.to_string(), data))
            }
        }
        Protocol::A2aLegacy => {
            let data = Value::String(format!("{code}{}", detail.summary()));
            (200, "application/json", jsonrpc_error(id, rpc_code(dir, reason), msg.to_string(), data))
        }
        Protocol::A2aV1JsonRpc => {
            let data = json!([detail.error_info(code)]);
            (200, "application/json", jsonrpc_error(id, rpc_code(dir, reason), msg.to_string(), data))
        }
        Protocol::A2aV1Http => {
            let (status, grpc) = match (dir, reason) {
                (Direction::Request, Reason::Secret) => (400, "INVALID_ARGUMENT"),
                (Direction::Request, Reason::Unscannable) => (413, "INVALID_ARGUMENT"),
                (Direction::Response, _) => (500, "INTERNAL"),
            };
            let v = json!({"error": {"code": status, "status": grpc, "message": msg, "details": [detail.error_info(code)]}});
            (status, "application/json", v)
        }
        Protocol::Llm(d) => {
            let status = match (dir, reason) {
                (Direction::Request, Reason::Secret) => 400,
                (Direction::Request, Reason::Unscannable) => 413,
                (Direction::Response, _) => 500,
            };
            (status, "application/json", llm_error(d, status, code, &format!("{msg}{}", detail.summary()), detail))
        }
    };
    Reply { status, content_type: ct, body: serde_json::to_vec(&body).unwrap_or_default() }
}

/// The provider-native error object, so vendor SDKs raise a regular
/// (non-retryable for 4xx) API error.
fn llm_error(d: Dialect, status: u32, code: &str, message: &str, detail: &Detail) -> Value {
    let kind = if status < 500 { "invalid_request_error" } else { "api_error" };
    match d {
        Dialect::OpenAi => json!({"error": {
            "message": message,
            "type": if status < 500 { "invalid_request_error" } else { "server_error" },
            "code": code.to_ascii_lowercase(),
            "param": null,
        }}),
        Dialect::Anthropic => json!({"type": "error", "error": {"type": kind, "message": message}}),
        Dialect::Gemini => {
            let grpc = if status < 500 { "INVALID_ARGUMENT" } else { "INTERNAL" };
            json!({"error": {"code": status, "status": grpc, "message": message, "details": [detail.error_info(code)]}})
        }
    }
}

/// The SSE event that ends a blocked LLM stream: `(event name, data)`.
pub fn llm_stream_event(d: Dialect, op: Option<&str>, reason: Reason, detail: &Detail) -> (Option<&'static str>, String) {
    let code = reason_code(reason, Direction::Response);
    let message = format!("{}{}", message(reason, Direction::Response), detail.summary());
    let (event, v) = match d {
        Dialect::OpenAi if op == Some("responses") => (
            Some("error"),
            json!({"type": "error", "code": code.to_ascii_lowercase(), "message": message, "param": null}),
        ),
        Dialect::OpenAi => (None, llm_error(d, 500, code, &message, detail)),
        Dialect::Anthropic => (Some("error"), llm_error(d, 500, code, &message, detail)),
        Dialect::Gemini => (None, llm_error(d, 500, code, &message, detail)),
    };
    (event, serde_json::to_string(&v).unwrap_or_default())
}

fn rpc_code(dir: Direction, reason: Reason) -> i64 {
    match (dir, reason) {
        (Direction::Request, Reason::Unscannable) => -32600,
        (Direction::Request, Reason::Secret) => -32602,
        (Direction::Response, _) => -32603,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Split so repository secret scanners do not flag the fixture.
    const RAW: &str = concat!("ghp", "_SECRETVALUEabcdefghijklmnopqrstuvwxyz");
    const FP: &str = "sha256:0123456789ab";

    fn hits() -> Vec<Hit> {
        vec![
            Hit { kind: "github_token".into(), location: "$.params.arguments.q".into(), fingerprint: FP.into() },
            Hit { kind: "github_token".into(), location: "query:token".into(), fingerprint: FP.into() },
        ]
    }

    fn body(r: &Reply) -> Value {
        serde_json::from_slice(&r.body).unwrap()
    }

    /// No error, in any shape, may carry a value or a fingerprint.
    fn assert_no_leak(r: &Reply) {
        let s = String::from_utf8(r.body.clone()).unwrap();
        assert!(!s.contains(RAW) && !s.contains("sha256:") && !s.contains("SECRETVALUE"), "{s}");
    }

    fn all(dir: Direction, reason: Reason, show: bool) -> Vec<Reply> {
        let h = hits();
        let d = Detail { hits: &h, show, domain: "p4a.ai" };
        let mut out: Vec<Reply> = [
            Protocol::Rest,
            Protocol::JsonRpc,
            Protocol::Mcp,
            Protocol::A2aLegacy,
            Protocol::A2aV1JsonRpc,
            Protocol::A2aV1Http,
            Protocol::Llm(Dialect::OpenAi),
            Protocol::Llm(Dialect::Anthropic),
            Protocol::Llm(Dialect::Gemini),
        ]
        .into_iter()
        .flat_map(|p| [build(p, Some("tools/call"), Some(&json!(1)), dir, reason, &d), build(p, None, None, dir, reason, &d)])
        .collect();
        for dialect in [Dialect::OpenAi, Dialect::Anthropic, Dialect::Gemini] {
            for op in [Some("responses"), None] {
                let (_, data) = llm_stream_event(dialect, op, reason, &d);
                out.push(Reply { status: 0, content_type: "text/event-stream", body: data.into_bytes() });
            }
        }
        out
    }

    #[test]
    fn nothing_leaks() {
        for dir in [Direction::Request, Direction::Response] {
            for reason in [Reason::Secret, Reason::Unscannable] {
                for show in [true, false] {
                    for r in all(dir, reason, show) {
                        assert_no_leak(&r);
                        if !show {
                            let s = String::from_utf8(r.body).unwrap();
                            assert!(!s.contains("github_token") && !s.contains("query:token"), "{s}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn mcp_request_block() {
        let h = hits();
        let d = Detail { hits: &h, show: true, domain: "p4a.ai" };
        let r = build(Protocol::Mcp, Some("tools/call"), Some(&json!(7)), Direction::Request, Reason::Secret, &d);
        assert_eq!(r.status, 200);
        let b = body(&r);
        assert_eq!(b["id"], 7);
        assert_eq!(b["error"]["code"], -32602);
        assert_eq!(b["error"]["data"]["reason"], "SECRET_DETECTED");
        assert_eq!(b["error"]["data"]["detectors"], json!(["github_token"]));
        assert_eq!(b["error"]["data"]["paths"], json!(["$.params.arguments.q", "query:token"]));
    }

    #[test]
    fn mcp_tools_call_response_is_error_result() {
        let h = hits();
        let d = Detail { hits: &h, show: true, domain: "p4a.ai" };
        let b = body(&build(Protocol::Mcp, Some("tools/call"), Some(&json!("x")), Direction::Response, Reason::Secret, &d));
        assert_eq!(b["result"]["isError"], true);
        assert!(b["result"]["content"][0]["text"].as_str().unwrap().contains("github_token"));
        let b = body(&build(Protocol::Mcp, Some("resources/read"), Some(&json!("x")), Direction::Response, Reason::Secret, &d));
        assert_eq!(b["error"]["code"], -32603);
    }

    #[test]
    fn a2a_shapes() {
        let h = hits();
        let d = Detail { hits: &h, show: true, domain: "example.com" };
        let b = body(&build(Protocol::A2aLegacy, None, Some(&json!("r1")), Direction::Request, Reason::Secret, &d));
        assert!(b["error"]["data"].as_str().unwrap().starts_with("SECRET_DETECTED (github_token at "));
        let b = body(&build(Protocol::A2aV1JsonRpc, None, Some(&json!("r1")), Direction::Response, Reason::Secret, &d));
        let info = &b["error"]["data"][0];
        assert_eq!(info["@type"], ERROR_INFO);
        assert_eq!(info["reason"], "SECRET_DETECTED_IN_RESPONSE");
        assert_eq!(info["domain"], "example.com");
        assert!(info["metadata"].as_object().unwrap().values().all(Value::is_string));
        let r = build(Protocol::A2aV1Http, None, None, Direction::Request, Reason::Secret, &d);
        assert_eq!(r.status, 400);
        let b = body(&r);
        assert_eq!(b["error"]["status"], "INVALID_ARGUMENT");
        assert_eq!(b["error"]["details"][0]["reason"], "SECRET_DETECTED");
    }

    #[test]
    fn llm_shapes() {
        let h = hits();
        let d = Detail { hits: &h, show: true, domain: "p4a.ai" };
        let r = build(Protocol::Llm(Dialect::OpenAi), None, None, Direction::Request, Reason::Secret, &d);
        assert_eq!((r.status, r.content_type), (400, "application/json"));
        let b = body(&r);
        assert_eq!(b["error"]["type"], "invalid_request_error");
        assert_eq!(b["error"]["code"], "secret_detected");
        assert!(b["error"]["message"].as_str().unwrap().contains("github_token"));
        let b = body(&build(Protocol::Llm(Dialect::Anthropic), None, None, Direction::Request, Reason::Unscannable, &d));
        assert_eq!((b["type"].clone(), b["error"]["type"].clone()), (json!("error"), json!("invalid_request_error")));
        let r = build(Protocol::Llm(Dialect::Gemini), None, None, Direction::Response, Reason::Secret, &d);
        let b = body(&r);
        assert_eq!((b["error"]["code"].clone(), b["error"]["status"].clone()), (json!(500), json!("INTERNAL")));
        assert_eq!(b["error"]["details"][0]["reason"], "SECRET_DETECTED_IN_RESPONSE");
        let (ev, data) = llm_stream_event(Dialect::Anthropic, None, Reason::Secret, &d);
        assert_eq!(ev, Some("error"));
        assert_eq!(serde_json::from_str::<Value>(&data).unwrap()["error"]["type"], "api_error");
        let (ev, data) = llm_stream_event(Dialect::OpenAi, Some("responses"), Reason::Secret, &d);
        assert_eq!(ev, Some("error"));
        assert_eq!(serde_json::from_str::<Value>(&data).unwrap()["type"], "error");
        let (ev, data) = llm_stream_event(Dialect::OpenAi, Some("chat.completions"), Reason::Secret, &d);
        assert_eq!(ev, None);
        assert_eq!(serde_json::from_str::<Value>(&data).unwrap()["error"]["type"], "server_error");
    }

    #[test]
    fn rest_and_unscannable() {
        let d = Detail { hits: &[], show: true, domain: "p4a.ai" };
        let r = build(Protocol::Rest, None, None, Direction::Request, Reason::Unscannable, &d);
        assert_eq!((r.status, r.content_type), (413, "application/problem+json"));
        let b = body(&build(Protocol::Mcp, None, Some(&json!(1)), Direction::Request, Reason::Unscannable, &d));
        assert_eq!((b["error"]["code"].clone(), b["error"]["data"]["reason"].clone()), (json!(-32600), json!("PAYLOAD_UNSCANNABLE")));
        let h = hits();
        let d = Detail { hits: &h, show: true, domain: "p4a.ai" };
        let b = body(&build(Protocol::Rest, None, None, Direction::Request, Reason::Secret, &d));
        assert_eq!(b["findings"][1], json!({"type": "github_token", "location": "query:token"}));
    }
}
