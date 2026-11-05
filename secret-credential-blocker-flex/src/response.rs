// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Response leg (only when `responseScanning.enabled`). Uses the split
//! headers → body states; the combined state can hang the response leg.

use pdk::hl::*;
use pdk::policy_violation::PolicyViolations;
use serde_json::Value;

use crate::errors::{self, Detail, Direction, Reason};
use crate::protocol::llm::{self, DeltaWindow};
use crate::protocol::{jsonrpc, Protocol};
use crate::redact;
use crate::report;
use crate::request::ExchangeCtx;
use crate::settings::{Action, ResponseSettings, Settings, SseMode};
use crate::sse::{Event, Outcome, SseRewriter};
use crate::walk::Hit;

enum Verdict {
    Clean,
    /// Findings, and the redacted text when redacting.
    Found(Vec<Hit>, Option<String>),
}

/// Scans one JSON or text payload (a whole body or one SSE `data` value).
fn scan_payload(s: &Settings, ctx: &ExchangeCtx, text: &str, redact: bool) -> Verdict {
    let walker = if matches!(ctx.protocol, Protocol::Llm(_)) { s.llm_walker(redact) } else { s.walker(redact, false) };
    match serde_json::from_str::<Value>(text) {
        Ok(mut doc) => {
            let hits = if ctx.protocol.is_jsonrpc() && jsonrpc::is_response(&doc) {
                let mut h = walker.walk_at(&mut doc, &["result"]);
                h.extend(walker.walk_at(&mut doc, &["error"]));
                h
            } else {
                walker.walk_at(&mut doc, &[])
            };
            if hits.is_empty() {
                return Verdict::Clean;
            }
            let out = redact.then(|| serde_json::to_string(&doc).ok()).flatten();
            Verdict::Found(hits, out)
        }
        Err(_) => {
            let findings = s.scanner.scan(text);
            if findings.is_empty() {
                return Verdict::Clean;
            }
            let hits = Hit::from_findings("body", &findings);
            Verdict::Found(hits, redact.then(|| redact::apply(text, &findings)))
        }
    }
}

/// The JSON-RPC id of a response payload, falling back to the request's.
fn id_of(text: &str, ctx: &ExchangeCtx) -> Option<Value> {
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .or_else(|| ctx.id.clone())
}

fn error_body(s: &Settings, ctx: &ExchangeCtx, id: Option<&Value>, reason: Reason, hits: &[Hit]) -> Vec<u8> {
    let detail = Detail { hits, show: s.error_detail, domain: &s.error_domain };
    errors::build(ctx.protocol, ctx.op.as_deref(), id, Direction::Response, reason, &detail).body
}

fn report_hits(r: &ResponseSettings, ctx: &ExchangeCtx, v: &PolicyViolations, hits: &[Hit]) {
    report::log_hits(Direction::Response, ctx.protocol.label(), ctx.op.as_deref(), r.action, hits);
    v.generate_policy_violation();
}

pub async fn response_filter(
    state: ResponseState,
    data: RequestData<Option<ExchangeCtx>>,
    s: &Settings,
    violations: &PolicyViolations,
) {
    let (RequestData::Continue(Some(ctx)), Some(r)) = (data, s.response.as_ref()) else {
        return;
    };
    let hs = state.into_headers_state().await;
    let h = hs.handler();
    let ct = h.header("content-type").unwrap_or_default().to_ascii_lowercase();
    let is_sse = ct.contains("text/event-stream");
    let is_text = ct.is_empty() || ct.contains("json") || ct.starts_with("text/") || ct.contains("xml");
    if !is_sse && !is_text {
        return;
    }
    let encoded = h
        .header("content-encoding")
        .map(|e| e.trim().to_ascii_lowercase())
        .is_some_and(|e| !e.is_empty() && e != "identity");
    let oversized = h
        .header("content-length")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .is_some_and(|n| n > s.max_body_bytes);
    if encoded || oversized {
        let why = if encoded { "content-encoding is not identity" } else { "content-length exceeds maxBodyBytes" };
        report::log_unscannable(Direction::Response, why, s.fail_closed);
        violations.generate_policy_violation();
        if s.fail_closed {
            // The replacement body is plain JSON: the encoding no longer applies.
            h.remove_header("content-length");
            h.remove_header("content-encoding");
            let bs = hs.into_body_state().await;
            let _ = bs.handler().set_body(&error_body(s, &ctx, ctx.id.as_ref(), Reason::Unscannable, &[]));
        }
        return;
    }
    let may_rewrite = r.action != Action::Monitor;
    if is_sse {
        let mode = if may_rewrite { r.sse_mode } else { SseMode::Monitor };
        if mode != SseMode::Monitor {
            h.remove_header("content-length");
        }
        match mode {
            SseMode::Stream => stream_sse(hs, s, r, &ctx, violations).await,
            SseMode::Buffer | SseMode::Monitor => {
                let bs = hs.into_body_state().await;
                let body = bs.handler().body();
                let mut rw = SseRewriter::default();
                let mut window = DeltaWindow::default();
                let mut f = |e: &Event| sse_event(s, r, &ctx, violations, e, &mut window);
                let mut out = rw.push(&body, &mut f);
                out.extend(rw.finish(&mut f));
                if mode == SseMode::Buffer && out != body && bs.handler().set_body(&out).is_err() {
                    pdk::logger::warn!("[secret-blocker] rewritten SSE body could not be written");
                }
            }
        }
        return;
    }
    if may_rewrite {
        h.remove_header("content-length");
    }
    let bs = hs.into_body_state().await;
    let body = bs.handler().body();
    if body.len() > s.max_body_bytes {
        report::log_unscannable(Direction::Response, "body exceeds maxBodyBytes", s.fail_closed);
        violations.generate_policy_violation();
        if s.fail_closed {
            let _ = bs.handler().set_body(&error_body(s, &ctx, ctx.id.as_ref(), Reason::Unscannable, &[]));
        }
        return;
    }
    let Ok(text) = std::str::from_utf8(&body) else { return };
    let Verdict::Found(hits, redacted) = scan_payload(s, &ctx, text, r.action == Action::Redact) else {
        return;
    };
    report_hits(r, &ctx, violations, &hits);
    let replacement = match (r.action, redacted) {
        (Action::Monitor, _) => return,
        (Action::Redact, Some(out)) => out.into_bytes(),
        _ => error_body(s, &ctx, id_of(text, &ctx).as_ref(), Reason::Secret, &hits),
    };
    if bs.handler().set_body(&replacement).is_err() {
        // Fall back to the (smaller) error body; never forward the original.
        let fallback = error_body(s, &ctx, id_of(text, &ctx).as_ref(), Reason::Secret, &hits);
        if bs.handler().set_body(&fallback).is_err() {
            pdk::logger::warn!("[secret-blocker] response body could not be replaced");
        }
    }
}

fn sse_event(
    s: &Settings,
    r: &ResponseSettings,
    ctx: &ExchangeCtx,
    v: &PolicyViolations,
    e: &Event,
    window: &mut DeltaWindow,
) -> Outcome {
    let Some(data) = e.data.as_deref() else { return Outcome::Keep };
    if data.trim() == "[DONE]" {
        return Outcome::Keep;
    }
    if let Protocol::Llm(d) = ctx.protocol {
        return llm_sse_event(s, r, ctx, v, d, data, window);
    }
    let Verdict::Found(hits, redacted) = scan_payload(s, ctx, data, r.action == Action::Redact) else {
        return Outcome::Keep;
    };
    report_hits(r, ctx, v, &hits);
    match (r.action, redacted) {
        (Action::Monitor, _) => Outcome::Keep,
        (Action::Redact, Some(out)) => Outcome::Replace(out),
        _ => {
            let body = error_body(s, ctx, id_of(data, ctx).as_ref(), Reason::Secret, &hits);
            Outcome::Terminate(String::from_utf8_lossy(&body).into_owned())
        }
    }
}

/// LLM streams: completion deltas are scanned as one running text, so a
/// secret emitted a few characters per event is still found. Other events
/// are scanned whole. A finding ends the stream with a provider-native error
/// event; redact acts as block because earlier tokens were already sent.
fn llm_sse_event(
    s: &Settings,
    r: &ResponseSettings,
    ctx: &ExchangeCtx,
    v: &PolicyViolations,
    d: llm::Dialect,
    data: &str,
    window: &mut DeltaWindow,
) -> Outcome {
    let hits = match serde_json::from_str::<Value>(data) {
        Ok(event) => {
            let deltas = llm::stream_deltas(d, &event);
            if deltas.is_empty() {
                match scan_payload(s, ctx, data, false) {
                    Verdict::Found(hits, _) => hits,
                    Verdict::Clean => return Outcome::Keep,
                }
            } else {
                Hit::from_findings("completion", &window.push(&s.scanner, &deltas))
            }
        }
        Err(_) => Hit::from_findings("completion", &window.push(&s.scanner, &[data])),
    };
    if hits.is_empty() {
        return Outcome::Keep;
    }
    report_hits(r, ctx, v, &hits);
    if r.action == Action::Monitor {
        return Outcome::Keep;
    }
    let detail = Detail { hits: &hits, show: s.error_detail, domain: &s.error_domain };
    match errors::llm_stream_event(d, ctx.op.as_deref(), Reason::Secret, &detail) {
        (Some(name), body) => Outcome::TerminateAs(name, body),
        (None, body) => Outcome::Terminate(body),
    }
}

async fn stream_sse(
    hs: ResponseHeadersState,
    s: &Settings,
    r: &ResponseSettings,
    ctx: &ExchangeCtx,
    v: &PolicyViolations,
) {
    let bs = hs.into_body_stream_state().await;
    let mut stream = bs.stream();
    let mut rw = SseRewriter::default();
    let mut window = DeltaWindow::default();
    let mut f = |e: &Event| sse_event(s, r, ctx, v, e, &mut window);
    while let Some(chunk) = stream.next().await {
        let out = rw.push(chunk.bytes(), &mut f);
        if out.as_slice() != chunk.bytes() && bs.write_chunk(Chunk::new(out)).is_err() {
            pdk::logger::warn!("[secret-blocker] SSE chunk could not be rewritten");
        }
    }
    // An unterminated trailing event stays held back: SSE clients discard
    // pending data at end of stream, so dropping it is spec-conformant.
    let _ = rw.finish(&mut f);
}
