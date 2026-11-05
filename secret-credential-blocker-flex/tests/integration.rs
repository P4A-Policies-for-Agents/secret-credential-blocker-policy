// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests on a real Flex Gateway (Docker). These also settle the
//! two runtime questions pdk-unit cannot: whether the request leg may rewrite
//! `:path` (query redaction) and whether `write_chunk` works on the response
//! leg (SSE stream mode).

mod common;

use common::setup::*;
use common::{aws_id, token};
use pdk_test::pdk_test;
use serde_json::{json, Value};

fn tools_call(args: Value) -> Value {
    json!({"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"search","arguments":args}})
}

async fn post(url: &str, body: Value, headers: &[(&str, &str)]) -> anyhow::Result<reqwest::Response> {
    let mut rb = reqwest::Client::new()
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_string());
    for (k, v) in headers {
        rb = rb.header(*k, *v);
    }
    Ok(rb.send().await?)
}

#[pdk_test]
async fn rest_block_and_clean_pass() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(json!({})).await?;
    let upstream = mock
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST).path("/orders");
            then.status(201).body("ok");
        })
        .await;

    let r = post(&format!("{url}/orders"), json!({"note": format!("key {}", aws_id())}), &[]).await?;
    assert_eq!(r.status(), 400);
    assert_eq!(r.headers()["content-type"], "application/problem+json");
    let body = r.text().await?;
    assert!(!body.contains(&aws_id()));
    upstream.assert_hits_async(0).await;

    let r = post(&format!("{url}/orders"), json!({"note": "deliver at noon"}), &[]).await?;
    assert_eq!(r.status(), 201);
    upstream.assert_hits_async(1).await;
    Ok(())
}

#[pdk_test]
async fn rest_redact_rewrites_the_upstream_body() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(json!({"action": "redact"})).await?;
    let upstream = mock
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST)
                .json_body(json!({"note": "key [REDACTED:aws_access_key_id]"}));
            then.status(200).body("ok");
        })
        .await;
    let r = post(&format!("{url}/orders"), json!({"note": format!("key {}", aws_id())}), &[]).await?;
    assert_eq!(r.status(), 200);
    upstream.assert_async().await;
    Ok(())
}

/// Spike: the request leg rewrites `:path` with the redacted query.
#[pdk_test]
async fn query_redact_rewrites_path() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(json!({"action": "redact"})).await?;
    let upstream = mock
        .mock_async(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/search")
                .query_param("token", "[REDACTED:github_token]");
            then.status(200).body("ok");
        })
        .await;
    let r = reqwest::get(format!("{url}/search?q=x&token={}", token())).await?;
    assert_eq!(r.status(), 200);
    upstream.assert_async().await;
    Ok(())
}

#[pdk_test]
async fn query_block() -> anyhow::Result<()> {
    let (_c, url, _mock) = setup_test(json!({})).await?;
    let r = reqwest::get(format!("{url}/search?token={}", token())).await?;
    assert_eq!(r.status(), 400);
    let b: Value = r.json().await?;
    assert_eq!(b["findings"][0]["location"], "query:token");
    Ok(())
}

#[pdk_test]
async fn multipart_block() -> anyhow::Result<()> {
    let (_c, url, _mock) = setup_test(json!({})).await?;
    let form = reqwest::multipart::Form::new()
        .text("note", aws_id())
        .part("file", reqwest::multipart::Part::bytes(vec![0u8, 1, 2]).file_name("x.bin").mime_str("application/octet-stream")?);
    let r = reqwest::Client::new().post(format!("{url}/upload")).multipart(form).send().await?;
    assert_eq!(r.status(), 400);
    let b: Value = r.json().await?;
    assert_eq!(b["findings"][0]["location"], "multipart:note");
    Ok(())
}

#[pdk_test]
async fn mcp_tools_call_block() -> anyhow::Result<()> {
    let (_c, url, _mock) = setup_test(json!({})).await?;
    let r = post(&format!("{url}/mcp"), tools_call(json!({"q": token()})), &[]).await?;
    assert_eq!(r.status(), 200);
    let b: Value = r.json().await?;
    assert_eq!((b["id"].clone(), b["error"]["code"].clone()), (json!(42), json!(-32602)));
    Ok(())
}

#[pdk_test]
async fn a2a_v03_v1_and_http_json() -> anyhow::Result<()> {
    let (_c, url, _mock) = setup_test(json!({})).await?;
    let v03 = json!({"jsonrpc":"2.0","id":"a","method":"message/send","params":{"message":{"parts":[{"kind":"text","text": token()}]}}});
    let b: Value = post(&format!("{url}/"), v03, &[]).await?.json().await?;
    assert!(b["error"]["data"].is_string());

    let v1 = json!({"jsonrpc":"2.0","id":"b","method":"SendMessage","params":{"message":{"parts":[{"text": token()}]}}});
    let b: Value = post(&format!("{url}/"), v1, &[("A2A-Version", "1.0")]).await?.json().await?;
    assert_eq!(b["error"]["data"][0]["reason"], "SECRET_DETECTED");

    let r = post(&format!("{url}/acme/message:send"), json!({"message":{"parts":[{"text": token()}]}}), &[("A2A-Version", "1.0")]).await?;
    assert_eq!(r.status(), 400);
    let b: Value = r.json().await?;
    assert_eq!(b["error"]["status"], "INVALID_ARGUMENT");
    Ok(())
}

#[pdk_test]
async fn mcp_response_block_is_error_result() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(json!({"responseScanning": {"enabled": true}})).await?;
    let leak = json!({"jsonrpc":"2.0","id":42,"result":{"content":[{"type":"text","text": format!("found {}", token())}]}});
    mock.mock_async(|when, then| {
        when.method(httpmock::Method::POST);
        then.status(200).header("content-type", "application/json").body(leak.to_string());
    })
    .await;
    let r = post(&format!("{url}/mcp"), tools_call(json!({"q": "hi"})), &[]).await?;
    let text = r.text().await?;
    assert!(!text.contains(&token()), "{text}");
    let b: Value = serde_json::from_str(&text)?;
    assert_eq!(b["result"]["isError"], true);
    Ok(())
}

fn sse_body() -> String {
    let ev = [
        json!({"jsonrpc":"2.0","id":"s","result":{"kind":"status-update","status":{"state":"working"}}}),
        json!({"jsonrpc":"2.0","id":"s","result":{"kind":"artifact-update","artifact":{"parts":[{"kind":"text","text": token()}]}}}),
        json!({"jsonrpc":"2.0","id":"s","result":{"kind":"status-update","final":true}}),
    ];
    ev.iter().map(|e| format!("data: {e}\n\n")).collect()
}

async fn sse_case(response: Value) -> anyhow::Result<String> {
    let (_c, url, mock) = setup_test(json!({"responseScanning": response})).await?;
    let body = sse_body();
    mock.mock_async(|when, then| {
        when.method(httpmock::Method::POST);
        then.status(200).header("content-type", "text/event-stream").body(body);
    })
    .await;
    let req = json!({"jsonrpc":"2.0","id":"s","method":"message/stream","params":{"message":{"parts":[{"kind":"text","text":"hi"}]}}});
    Ok(post(&format!("{url}/"), req, &[]).await?.text().await?)
}

/// Spike: `write_chunk` rewrites events on the streaming response leg.
#[pdk_test]
async fn sse_stream_redact() -> anyhow::Result<()> {
    let s = sse_case(json!({"enabled": true, "action": "redact"})).await?;
    assert!(s.contains("[REDACTED:github_token]") && !s.contains(&token()), "{s}");
    assert_eq!(s.matches("data: ").count(), 3, "{s}");
    Ok(())
}

#[pdk_test]
async fn sse_stream_block_terminates() -> anyhow::Result<()> {
    let s = sse_case(json!({"enabled": true})).await?;
    assert!(!s.contains(&token()), "{s}");
    assert!(s.contains("SECRET_DETECTED_IN_RESPONSE") && !s.contains("\"final\":true"), "{s}");
    Ok(())
}

#[pdk_test]
async fn sse_buffer_redact() -> anyhow::Result<()> {
    let s = sse_case(json!({"enabled": true, "action": "redact", "sseMode": "buffer"})).await?;
    assert!(s.contains("[REDACTED:github_token]") && !s.contains(&token()), "{s}");
    Ok(())
}
