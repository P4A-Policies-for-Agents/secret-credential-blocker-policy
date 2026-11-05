// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Request leg: headers and query at the headers stage, then the body.

use pdk::hl::*;
use pdk::policy_violation::PolicyViolations;
use serde_json::Value;

use crate::errors::{self, Detail, Direction, Reason};
use crate::protocol::{self, a2a, llm, multipart, query, BodyPlan, Protocol, RequestMeta};
use crate::redact;
use crate::report;
use crate::settings::{Action, Settings};
use crate::walk::Hit;

/// Carried from the request leg to the response leg.
#[derive(Debug, Clone)]
pub struct ExchangeCtx {
    pub protocol: Protocol,
    pub op: Option<String>,
    pub id: Option<Value>,
}

struct Target<'a> {
    protocol: Protocol,
    op: Option<&'a str>,
    id: Option<&'a Value>,
}

fn reply(s: &Settings, t: &Target, reason: Reason, hits: &[Hit]) -> Response {
    let detail = Detail { hits, show: s.error_detail, domain: &s.error_domain };
    let r = errors::build(t.protocol, t.op, t.id, Direction::Request, reason, &detail);
    Response::new(r.status)
        .with_headers(vec![("content-type".to_string(), r.content_type.to_string())])
        .with_body(r.body)
}

fn is_encoded(h: &dyn HeadersHandler) -> bool {
    h.header("content-encoding")
        .map(|e| e.trim().to_ascii_lowercase())
        .is_some_and(|e| !e.is_empty() && e != "identity")
}

pub async fn request_filter(
    state: RequestState,
    s: &Settings,
    violations: &PolicyViolations,
) -> Flow<Option<ExchangeCtx>> {
    let hs = state.into_headers_state().await;
    let h = hs.handler();
    let full_path = hs.path();
    let (path, query_str) = query::split_path(&full_path);
    let meta = RequestMeta {
        method: hs.method().to_ascii_uppercase(),
        path: path.to_string(),
        content_type: h.header("content-type").unwrap_or_default().trim().to_ascii_lowercase(),
        is_v1: a2a::is_v1(h.header("a2a-version").as_deref(), query_str),
        llm: h
            .header("x-llm-input-format")
            .or_else(|| h.header("x-input-format"))
            .as_deref()
            .and_then(llm::Dialect::from_header),
    };
    let (prov, prov_op) = protocol::provisional(s.mode, &meta);
    let provisional = Target { protocol: prov, op: prov_op, id: None };
    let redact = s.action == Action::Redact;
    let mut hits: Vec<Hit> = Vec::new();

    for name in &s.headers {
        if s.skip.header(name) {
            continue;
        }
        let Some(value) = h.header(name) else { continue };
        let findings = s.scanner.scan_field(name, &value, false);
        if findings.is_empty() {
            continue;
        }
        hits.extend(Hit::from_findings(&format!("header:{name}"), &findings));
        if redact {
            h.set_header(name, &redact::apply(&value, &findings));
        }
    }

    if s.query_params && !query_str.is_empty() {
        let walker = s.walker(redact, false);
        let r = query::scan(query_str, "query:", &walker, |n| s.skip.query(n));
        hits.extend(r.hits);
        if let Some(q) = r.rewritten {
            h.set_header(":path", &format!("{path}?{q}"));
        }
    }

    let has_body = hs.contains_body() && !meta.is_grpc();
    let oversized = h
        .header("content-length")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .is_some_and(|n| n > s.max_body_bytes);
    let unscannable = if !has_body {
        None
    } else if is_encoded(h) {
        Some("content-encoding is not identity")
    } else if oversized {
        Some("content-length exceeds maxBodyBytes")
    } else {
        None
    };

    // Block on a header/query hit right away unless the body is needed to
    // answer in the right JSON-RPC envelope.
    let wants_envelope = has_body
        && unscannable.is_none()
        && meta.method == "POST"
        && prov == Protocol::Rest
        && s.mode != protocol::Mode::Rest;
    if !hits.is_empty() && s.action == Action::Block && !wants_envelope {
        return conclude(s, violations, &provisional, &hits, None, None);
    }

    if let Some(why) = unscannable {
        report::log_unscannable(Direction::Request, why, s.fail_closed);
        violations.generate_policy_violation();
        if s.fail_closed {
            return Flow::Break(reply(s, &provisional, Reason::Unscannable, &[]));
        }
        return conclude(s, violations, &provisional, &hits, None, None);
    }
    if !has_body {
        return conclude(s, violations, &provisional, &hits, None, None);
    }

    if redact {
        h.remove_header("content-length");
    }
    let bs = hs.into_body_state().await;
    let body = bs.handler().body();
    if body.len() > s.max_body_bytes {
        report::log_unscannable(Direction::Request, "body exceeds maxBodyBytes", s.fail_closed);
        violations.generate_policy_violation();
        if s.fail_closed {
            return Flow::Break(reply(s, &provisional, Reason::Unscannable, &[]));
        }
        return conclude(s, violations, &provisional, &hits, None, None);
    }

    let mut c = protocol::classify(s.mode, &meta, &body, s.rest_body, s.multipart);
    let target_op = c.op.clone();
    let target_id = c.id.clone();
    let target = Target { protocol: c.protocol, op: target_op.as_deref(), id: target_id.as_ref() };
    let before = hits.len();
    let rewritten: Option<Vec<u8>> = match &c.plan {
        BodyPlan::Json { roots, push_config } => {
            let walker = if matches!(c.protocol, Protocol::Llm(_)) { s.llm_walker(redact) } else { s.walker(redact, *push_config) };
            match c.doc.as_mut() {
                Some(doc) => {
                    for root in roots {
                        hits.extend(walker.walk_at(doc, root));
                    }
                    (redact && hits.len() > before).then(|| serde_json::to_vec(doc).ok()).flatten()
                }
                None => None,
            }
        }
        BodyPlan::Llm(d) => {
            let walker = s.llm_walker(redact);
            match c.doc.as_mut() {
                Some(doc) => {
                    hits.extend(llm::scan_request(doc, *d, s.llm_latest_turn, &walker));
                    (redact && hits.len() > before).then(|| serde_json::to_vec(doc).ok()).flatten()
                }
                None => None,
            }
        }
        BodyPlan::Form => match std::str::from_utf8(&body) {
            Ok(text) => {
                let walker = s.walker(redact, false);
                let r = query::scan(text, "form:", &walker, |n| s.skip.form(n));
                hits.extend(r.hits);
                r.rewritten.map(String::into_bytes)
            }
            Err(_) => None,
        },
        BodyPlan::Multipart(boundary) => match multipart::scan(&body, boundary, &s.walker(redact, false)) {
            Ok(r) => {
                hits.extend(r.hits);
                r.rewritten
            }
            Err(_) => {
                report::log_unscannable(Direction::Request, "malformed multipart body", s.fail_closed);
                violations.generate_policy_violation();
                if s.fail_closed {
                    return Flow::Break(reply(s, &target, Reason::Unscannable, &[]));
                }
                None
            }
        },
        BodyPlan::Text => match std::str::from_utf8(&body) {
            Ok(text) if !s.skip.json(&crate::path::JsonPath::root()) => {
                let findings = s.scanner.scan(text);
                hits.extend(Hit::from_findings("body", &findings));
                (redact && !findings.is_empty()).then(|| redact::apply(text, &findings).into_bytes())
            }
            _ => None,
        },
        BodyPlan::Skip => None,
    };
    conclude(s, violations, &target, &hits, rewritten.as_deref(), Some(bs.handler()))
}

fn conclude(
    s: &Settings,
    violations: &PolicyViolations,
    t: &Target,
    hits: &[Hit],
    new_body: Option<&[u8]>,
    body: Option<&dyn BodyHandler>,
) -> Flow<Option<ExchangeCtx>> {
    if !hits.is_empty() {
        report::log_hits(Direction::Request, t.protocol.label(), t.op, s.action, hits);
        violations.generate_policy_violation();
        match s.action {
            Action::Block => return Flow::Break(reply(s, t, Reason::Secret, hits)),
            Action::Redact => {
                if let (Some(new_body), Some(handler)) = (new_body, body) {
                    if handler.set_body(new_body).is_err() {
                        // Never forward the unredacted body.
                        pdk::logger::warn!("[secret-blocker] redacted request body could not be written; blocking");
                        return Flow::Break(reply(s, t, Reason::Secret, hits));
                    }
                }
            }
            Action::Monitor => {}
        }
    }
    Flow::Continue(s.response.as_ref().map(|_| ExchangeCtx {
        protocol: t.protocol,
        op: t.op.map(str::to_string),
        id: t.id.cloned(),
    }))
}
