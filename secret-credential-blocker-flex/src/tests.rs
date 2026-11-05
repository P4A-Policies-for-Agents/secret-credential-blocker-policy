// Copyright 2026 Salesforce, Inc. All rights reserved.
//! pdk-unit tests (in-process; no Docker).

use pdk_unit::{UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder};
use serde_json::{json, Value};

// Fixtures are assembled at runtime so repository secret scanners do not flag this file.
fn token() -> String {
    ["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"].concat()
}

fn aws_id() -> String {
    ["AKIA", "IOSFODNN7EXAMPLQ"].concat()
}

/// Echoes the request: body as-is, `:path` and `x-debug` in response headers.
fn echo(req: UnitHttpRequest) -> UnitHttpResponse {
    let path = req.header(":path").unwrap_or_default().to_string();
    let debug = req.header("x-debug").unwrap_or_default().to_string();
    UnitHttpResponse::new(200)
        .with_header("content-type", "application/json")
        .with_header("x-echo-path", path)
        .with_header("x-echo-debug", debug)
        .with_body(req.body().to_vec())
}

fn tester(config: Value) -> pdk_unit::UnitTest {
    UnitTestBuilder::default()
        .with_config(config.to_string())
        .with_backend(echo)
        .with_entrypoint(crate::configure)
}

fn tester_with(config: Value, backend: impl Fn(UnitHttpRequest) -> UnitHttpResponse + 'static) -> pdk_unit::UnitTest {
    UnitTestBuilder::default()
        .with_config(config.to_string())
        .with_backend(backend)
        .with_entrypoint(crate::configure)
}

fn post(path: &str, body: Value) -> UnitHttpRequest {
    UnitHttpRequest::post()
        .with_path(path)
        .with_header("content-type", "application/json")
        .with_body(body.to_string())
}

fn json_of(r: &UnitHttpResponse) -> Value {
    serde_json::from_slice(r.body()).unwrap_or(Value::Null)
}

fn assert_no_leak(t: &pdk_unit::UnitTest, r: &UnitHttpResponse, secret: &str) {
    let body = String::from_utf8_lossy(r.body());
    assert!(!body.contains(secret), "response leaks the secret: {body}");
    for line in t.logs() {
        assert!(!line.contains(secret), "log leaks the secret: {line}");
    }
}

fn tools_call(args: Value) -> Value {
    json!({"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"search","arguments":args}})
}

#[test]
fn clean_request_passes_untouched() {
    let mut t = tester(json!({}));
    let body = json!({"order": {"id": 7, "note": "deliver at noon"}});
    let r = t.request(post("/orders", body.clone()));
    assert_eq!(r.status_code(), 200);
    assert_eq!(json_of(&r), body);
}

#[test]
fn rest_body_block() {
    let mut t = tester(json!({}));
    let r = t.request(post("/orders", json!({"note": format!("key {}", aws_id())})));
    assert_eq!(r.status_code(), 400);
    assert_eq!(r.header("content-type"), Some("application/problem+json"));
    let b = json_of(&r);
    assert_eq!(b["findings"][0], json!({"type": "aws_access_key_id", "location": "$.note"}));
    assert_no_leak(&t, &r, &aws_id());
    assert!(t.logs().iter().any(|l| l.contains("detector=aws_access_key_id") && l.contains("fingerprint=sha256:")));
}

#[test]
fn rest_body_redact() {
    let mut t = tester(json!({"action": "redact"}));
    let r = t.request(post("/orders", json!({"note": format!("key {}", aws_id()), "n": 1})));
    assert_eq!(r.status_code(), 200);
    assert_eq!(json_of(&r), json!({"note": "key [REDACTED:aws_access_key_id]", "n": 1}));
}

#[test]
fn monitor_forwards_and_logs() {
    let mut t = tester(json!({"action": "monitor"}));
    let body = json!({"note": token()});
    let r = t.request(post("/orders", body.clone()));
    assert_eq!(json_of(&r), body);
    assert!(t.logs().iter().any(|l| l.contains("action=monitor") && l.contains("detector=github_token")));
    assert!(t.logs().iter().all(|l| !l.contains(&token())));
}

#[test]
fn mcp_tools_call_block() {
    let mut t = tester(json!({}));
    let r = t.request(post("/mcp", tools_call(json!({"q": format!("use {}", token())}))));
    assert_eq!(r.status_code(), 200);
    let b = json_of(&r);
    assert_eq!(b["id"], 42);
    assert_eq!(b["error"]["code"], -32602);
    assert_eq!(b["error"]["data"]["paths"], json!(["$.params.arguments.q"]));
    assert_no_leak(&t, &r, &token());
}

#[test]
fn mcp_tool_name_is_not_scanned() {
    let mut t = tester(json!({}));
    let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name": token(),"arguments":{}}});
    assert_eq!(json_of(&t.request(post("/mcp", body.clone()))), body);
}

#[test]
fn a2a_v03_message_send_with_file_bytes() {
    use base64::Engine;
    let mut t = tester(json!({}));
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("cfg={}", aws_id()));
    let body = json!({"jsonrpc":"2.0","id":"r1","method":"message/send","params":{"message":{"role":"user","parts":[
        {"kind":"text","text":"see attached"},
        {"kind":"file","file":{"name":"a.env","mimeType":"text/plain","bytes":encoded}}
    ]}}});
    let b = json_of(&t.request(post("/", body)));
    assert_eq!(b["id"], "r1");
    assert_eq!(b["error"]["code"], -32602);
    let data = b["error"]["data"].as_str().unwrap();
    assert!(data.contains("$.params.message.parts[1].file.bytes(base64)"), "{data}");
}

#[test]
fn a2a_v1_jsonrpc_error_info() {
    let mut t = tester(json!({"errorDomain": "example.com"}));
    let body = json!({"jsonrpc":"2.0","id":"r2","method":"SendMessage","params":{"message":{"parts":[{"text": token()}]}}});
    let req = post("/", body).with_header("A2A-Version", "1.0");
    let b = json_of(&t.request(req));
    let info = &b["error"]["data"][0];
    assert_eq!(info["@type"], "type.googleapis.com/google.rpc.ErrorInfo");
    assert_eq!((info["reason"].clone(), info["domain"].clone()), (json!("SECRET_DETECTED"), json!("example.com")));
}

#[test]
fn a2a_v1_http_json_status() {
    let mut t = tester(json!({}));
    let req = post("/acme/message:send", json!({"message":{"parts":[{"text": token()}]}})).with_header("a2a-version", "1.0");
    let r = t.request(req);
    assert_eq!(r.status_code(), 400);
    assert_eq!(json_of(&r)["error"]["status"], "INVALID_ARGUMENT");
}

#[test]
fn a2a_push_config_credentials_are_skipped_but_url_scanned() {
    let mut t = tester(json!({}));
    let ok = json!({"jsonrpc":"2.0","id":1,"method":"tasks/pushNotificationConfig/set","params":{"taskId":"t1",
        "pushNotificationConfig":{"url":"https://hooks.example.org/a","token": token(),"authentication":{"schemes":["Bearer"],"credentials": token()}}}});
    assert_eq!(json_of(&t.request(post("/", ok.clone()))), ok);
    let bad = json!({"jsonrpc":"2.0","id":1,"method":"tasks/pushNotificationConfig/set","params":{"taskId":"t1",
        "pushNotificationConfig":{"url": format!("https://hooks.example.org/a?t={}", token())}}});
    assert_eq!(json_of(&t.request(post("/", bad)))["error"]["code"], -32602);
}

#[test]
fn query_block_and_skip() {
    let mut t = tester(json!({}));
    let r = t.request(UnitHttpRequest::get().with_path(&format!("/search?q=x&token={}", token())));
    assert_eq!(r.status_code(), 400);
    assert_eq!(json_of(&r)["findings"][0]["location"], "query:token");
    let mut t = tester(json!({"allowlist": {"skipPaths": ["query:token"]}}));
    let r = t.request(UnitHttpRequest::get().with_path(&format!("/search?token={}", token())));
    assert_eq!(r.status_code(), 200);
}

#[test]
fn query_redact_rewrites_path() {
    let mut t = tester(json!({"action": "redact"}));
    let r = t.request(UnitHttpRequest::get().with_path(&format!("/search?q=x&token={}", token())));
    assert_eq!(r.status_code(), 200);
    assert_eq!(r.header("x-echo-path"), Some("/search?q=x&token=%5BREDACTED%3Agithub_token%5D"));
}

#[test]
fn query_hit_on_jsonrpc_post_uses_the_envelope() {
    let mut t = tester(json!({}));
    let r = t.request(post(&format!("/mcp?api_key={}", token()), tools_call(json!({"q": "hi"}))));
    let b = json_of(&r);
    assert_eq!((r.status_code(), b["id"].clone(), b["error"]["code"].clone()), (200, json!(42), json!(-32602)));
}

#[test]
fn configured_header_scanned_authorization_never() {
    let mut t = tester(json!({"scan": {"headers": ["X-Debug", "Authorization"]}}));
    let ok = UnitHttpRequest::get().with_path("/").with_header("authorization", format!("Bearer {}", token()));
    assert_eq!(t.request(ok).status_code(), 200);
    let bad = UnitHttpRequest::get().with_path("/").with_header("x-debug", token());
    let r = t.request(bad);
    assert_eq!(r.status_code(), 400);
    assert_eq!(json_of(&r)["findings"][0]["location"], "header:x-debug");
    let mut t = tester(json!({"action": "redact", "scan": {"headers": ["x-debug"]}}));
    let r = t.request(UnitHttpRequest::get().with_path("/").with_header("x-debug", token()));
    assert_eq!(r.header("x-echo-debug"), Some("[REDACTED:github_token]"));
}

#[test]
fn form_body() {
    let mut t = tester(json!({"action": "redact"}));
    let req = UnitHttpRequest::post()
        .with_path("/login")
        .with_header("content-type", "application/x-www-form-urlencoded")
        .with_body(format!("user=bob&note={}", token()));
    let r = t.request(req);
    assert_eq!(String::from_utf8_lossy(r.body()), "user=bob&note=%5BREDACTED%3Agithub_token%5D");
}

#[test]
fn multipart_block_and_binary_skip() {
    let mut t = tester(json!({}));
    let body = format!(
        "--b1\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n{}\r\n--b1--\r\n",
        aws_id()
    );
    let req = UnitHttpRequest::post()
        .with_path("/upload")
        .with_header("content-type", "multipart/form-data; boundary=b1")
        .with_body(body);
    let r = t.request(req);
    assert_eq!(r.status_code(), 400);
    assert_eq!(json_of(&r)["findings"][0]["location"], "multipart:note");
    let mut bin = b"--b1\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec();
    bin.extend_from_slice(aws_id().as_bytes());
    bin.extend_from_slice(b"\r\n--b1--\r\n");
    let req = UnitHttpRequest::post()
        .with_path("/upload")
        .with_header("content-type", "multipart/form-data; boundary=b1")
        .with_body(bin);
    assert_eq!(t.request(req).status_code(), 200);
}

#[test]
fn error_detail_off_hides_detectors() {
    let mut t = tester(json!({"errorDetail": false}));
    let r = t.request(post("/orders", json!({"note": token()})));
    let s = String::from_utf8_lossy(r.body());
    assert!(!s.contains("github_token") && !s.contains("$.note"), "{s}");
}

#[test]
fn oversize_fail_open_and_closed() {
    let big = json!({"pad": "x".repeat(2048), "note": token()});
    let mut t = tester(json!({"maxBodyBytes": 1024}));
    assert_eq!(t.request(post("/orders", big.clone())).status_code(), 200);
    let mut t = tester(json!({"maxBodyBytes": 1024, "oversizeBehavior": "failClosed"}));
    assert_eq!(t.request(post("/orders", big)).status_code(), 413);
}

#[test]
fn gzip_request_is_unscannable() {
    let mut t = tester(json!({"oversizeBehavior": "failClosed"}));
    let req = post("/orders", json!({"note": token()})).with_header("content-encoding", "gzip");
    assert_eq!(t.request(req).status_code(), 413);
}

#[test]
fn invalid_config_fails_to_load() {
    let built = std::panic::catch_unwind(|| {
        let mut t = tester(json!({"customPatterns": [{"name": "x", "regex": "("}]}));
        t.request(post("/", json!({}))).status_code()
    });
    // pdk-unit surfaces a configure error as a panic or a non-200; either way no pass-through.
    if let Ok(status) = built {
        assert_ne!(status, 200);
    }
}

// ── Response leg ────────────────────────────────────────────────────────────

fn leaking_tool(_: UnitHttpRequest) -> UnitHttpResponse {
    UnitHttpResponse::new(200)
        .with_header("content-type", "application/json")
        .with_body(json!({"jsonrpc":"2.0","id":42,"result":{"content":[{"type":"text","text": format!("found {}", token())}]}}).to_string())
}

#[test]
fn response_scanning_off_by_default() {
    let mut t = tester_with(json!({}), leaking_tool);
    let r = t.request(post("/mcp", tools_call(json!({"q": "hi"}))));
    assert!(String::from_utf8_lossy(r.body()).contains(&token()));
}

#[test]
fn mcp_response_block_is_error_result() {
    let mut t = tester_with(json!({"responseScanning": {"enabled": true}}), leaking_tool);
    let r = t.request(post("/mcp", tools_call(json!({"q": "hi"}))));
    let b = json_of(&r);
    assert_eq!(b["id"], 42);
    assert_eq!(b["result"]["isError"], true);
    assert_no_leak(&t, &r, &token());
}

#[test]
fn mcp_response_redact() {
    let mut t = tester_with(json!({"responseScanning": {"enabled": true, "action": "redact"}}), leaking_tool);
    let b = json_of(&t.request(post("/mcp", tools_call(json!({"q": "hi"})))));
    assert_eq!(b["result"]["content"][0]["text"], "found [REDACTED:github_token]");
}

fn sse_backend(_: UnitHttpRequest) -> UnitHttpResponse {
    let ev1 = json!({"jsonrpc":"2.0","id":"s","result":{"kind":"status-update","status":{"state":"working"}}});
    let ev2 = json!({"jsonrpc":"2.0","id":"s","result":{"kind":"artifact-update","artifact":{"parts":[{"kind":"text","text": token()}]}}});
    let ev3 = json!({"jsonrpc":"2.0","id":"s","result":{"kind":"status-update","final":true}});
    UnitHttpResponse::new(200)
        .with_header("content-type", "text/event-stream")
        .with_body(format!("data: {ev1}\n\ndata: {ev2}\n\ndata: {ev3}\n\n"))
}

fn stream_request() -> UnitHttpRequest {
    post("/", json!({"jsonrpc":"2.0","id":"s","method":"message/stream","params":{"message":{"parts":[{"kind":"text","text":"hi"}]}}}))
}

#[test]
fn sse_buffer_redact() {
    let mut t = tester_with(json!({"responseScanning": {"enabled": true, "action": "redact", "sseMode": "buffer"}}), sse_backend);
    let r = t.request(stream_request());
    let s = String::from_utf8_lossy(r.body()).into_owned();
    assert!(s.contains("[REDACTED:github_token]") && !s.contains(&token()), "{s}");
    assert_eq!(s.matches("data: ").count(), 3);
}

#[test]
fn sse_stream_block_terminates() {
    let mut t = tester_with(json!({"responseScanning": {"enabled": true}}), sse_backend);
    t.set_chunk_size(40);
    let r = t.request(stream_request());
    let s = String::from_utf8_lossy(r.body()).into_owned();
    assert!(!s.contains(&token()), "{s}");
    assert!(s.contains("SECRET_DETECTED_IN_RESPONSE") && !s.contains("\"final\":true"), "{s}");
}

#[test]
fn sse_monitor_passes_through() {
    let mut t = tester_with(json!({"responseScanning": {"enabled": true, "sseMode": "monitor"}}), sse_backend);
    let r = t.request(stream_request());
    assert!(String::from_utf8_lossy(r.body()).contains(&token()));
    assert!(t.logs().iter().any(|l| l.contains("response") && l.contains("detector=github_token")));
}

// ── LLM traffic ─────────────────────────────────────────────────────────────

fn llm_post(path: &str, format: &str, body: Value) -> UnitHttpRequest {
    post(path, body).with_header("x-llm-input-format", format)
}

fn openai_chat(text: &str) -> Value {
    json!({"model": "gpt-4o", "messages": [{"role": "user", "content": text}]})
}

#[test]
fn llm_openai_request_block() {
    let mut t = tester(json!({}));
    let r = t.request(llm_post("/v1/chat/completions", "openai", openai_chat(&format!("deploy with {}", aws_id()))));
    assert_eq!(r.status_code(), 400);
    assert_eq!(r.header("content-type"), Some("application/json"));
    let b = json_of(&r);
    assert_eq!(b["error"]["type"], "invalid_request_error");
    assert_eq!(b["error"]["code"], "secret_detected");
    assert!(b["error"]["message"].as_str().unwrap().contains("$.messages[0].content"));
    assert_no_leak(&t, &r, &aws_id());
    assert!(t.logs().iter().any(|l| l.contains("llm-openai op=chat.completions") && l.contains("detector=aws_access_key_id")));
}

#[test]
fn llm_anthropic_redact_and_parameters_untouched() {
    let mut t = tester(json!({"action": "redact"}));
    let body = json!({
        "model": "claude-x", "max_tokens": 64, "system": "be brief",
        "messages": [{"role": "user", "content": [{"type": "text", "text": format!("token {}", token())}]}]
    });
    let r = t.request(llm_post("/v1/messages", "Anthropic", body.clone()));
    assert_eq!(r.status_code(), 200);
    let mut expected = body;
    expected["messages"][0]["content"][0]["text"] = json!("token [REDACTED:github_token]");
    assert_eq!(json_of(&r), expected);
}

#[test]
fn llm_gemini_block_and_x_input_format_header() {
    let mut t = tester(json!({}));
    let body = json!({"contents": [{"role": "user", "parts": [{"text": format!("my key {}", token())}]}]});
    let r = t.request(post("/v1beta/models/gemini-pro:generateContent", body).with_header("x-input-format", "gemini"));
    assert_eq!(r.status_code(), 400);
    let b = json_of(&r);
    assert_eq!((b["error"]["code"].clone(), b["error"]["status"].clone()), (json!(400), json!("INVALID_ARGUMENT")));
    assert_eq!(b["error"]["details"][0]["reason"], "SECRET_DETECTED");
}

#[test]
fn llm_latest_turn_ignores_resent_history() {
    let body = json!({"model": "m", "messages": [
        {"role": "user", "content": format!("old {}", token())},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": "thanks"}
    ]});
    let mut t = tester(json!({"llm": {"scanScope": "latestTurn"}}));
    assert_eq!(t.request(llm_post("/v1/chat/completions", "openai", body.clone())).status_code(), 200);
    let mut t = tester(json!({}));
    assert_eq!(t.request(llm_post("/v1/chat/completions", "openai", body)).status_code(), 400);
}

#[test]
fn llm_forced_mode_without_header() {
    let mut t = tester(json!({"protocol": "llm"}));
    let r = t.request(post("/v1/chat/completions", openai_chat(&token())));
    assert_eq!(json_of(&r)["error"]["code"], "secret_detected");
    // Without the header and in auto mode the same request is REST.
    let mut t = tester(json!({}));
    let r = t.request(post("/v1/chat/completions", openai_chat(&token())));
    assert_eq!(r.header("content-type"), Some("application/problem+json"));
}

fn leaking_completion(_: UnitHttpRequest) -> UnitHttpResponse {
    UnitHttpResponse::new(200)
        .with_header("content-type", "application/json")
        .with_body(json!({"id": "c1", "choices": [{"index": 0, "message": {"role": "assistant", "content": format!("use {}", token())}}]}).to_string())
}

#[test]
fn llm_response_block_and_redact() {
    let mut t = tester_with(json!({"responseScanning": {"enabled": true}}), leaking_completion);
    let r = t.request(llm_post("/v1/chat/completions", "openai", openai_chat("hi")));
    let b = json_of(&r);
    assert_eq!(b["error"]["type"], "server_error");
    assert_no_leak(&t, &r, &token());
    let mut t = tester_with(json!({"responseScanning": {"enabled": true, "action": "redact"}}), leaking_completion);
    let b = json_of(&t.request(llm_post("/v1/chat/completions", "openai", openai_chat("hi"))));
    assert_eq!(b["choices"][0]["message"]["content"], "use [REDACTED:github_token]");
}

/// Streams the token a few characters per event, Anthropic-style.
fn anthropic_stream(_: UnitHttpRequest) -> UnitHttpResponse {
    let mut s = String::from("event: message_start\ndata: {\"type\":\"message_start\"}\n\n");
    let text = format!("here: {} end", token());
    for piece in text.as_bytes().chunks(5) {
        let d = json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": String::from_utf8_lossy(piece)}});
        s.push_str(&format!("event: content_block_delta\ndata: {d}\n\n"));
    }
    s.push_str("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
    UnitHttpResponse::new(200).with_header("content-type", "text/event-stream").with_body(s)
}

#[test]
fn llm_stream_secret_split_across_deltas_terminates() {
    // Redact acts as block on LLM streams.
    let mut t = tester_with(json!({"responseScanning": {"enabled": true, "action": "redact"}}), anthropic_stream);
    t.set_chunk_size(64);
    let body = json!({"model": "c", "max_tokens": 9, "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let r = t.request(llm_post("/v1/messages", "anthropic", body));
    let s = String::from_utf8_lossy(r.body()).into_owned();
    assert!(s.contains("event: error\ndata: {\"type\":\"error\""), "{s}");
    assert!(!s.contains("message_stop"), "{s}");
    assert!(t.logs().iter().any(|l| l.contains("llm-anthropic") && l.contains("location=completion")));
    assert_no_leak(&t, &r, &token());
}
