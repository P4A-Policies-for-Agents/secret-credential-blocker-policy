// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Query-string (and `application/x-www-form-urlencoded`) scanning.

use std::borrow::Cow;

use crate::redact;
use crate::walk::{Hit, Walker};

pub struct FormScan {
    pub hits: Vec<Hit>,
    /// The re-encoded string when redaction changed something.
    pub rewritten: Option<String>,
}

/// Splits a `:path` value into path and query (without `?`).
pub fn split_path(full: &str) -> (&str, &str) {
    match full.split_once('?') {
        Some((p, q)) => (p, q),
        None => (full, ""),
    }
}

fn decode(raw: &str) -> String {
    form_urlencoded::parse(raw.as_bytes())
        .next()
        .map(|(k, _)| k.into_owned())
        .unwrap_or_default()
}

/// Scans each `name=value` pair. `prefix` builds locations (`query:`, or
/// `multipart:<part>.` for a urlencoded part). Untouched pairs keep their
/// original encoding when the string is rewritten.
pub fn scan(raw: &str, prefix: &str, walker: &Walker, skip: impl Fn(&str) -> bool) -> FormScan {
    let mut hits = Vec::new();
    let mut changed = false;
    let mut out: Vec<Cow<str>> = Vec::new();
    for seg in raw.split('&') {
        let (raw_name, raw_value) = seg.split_once('=').unwrap_or((seg, ""));
        let name = decode(raw_name);
        if seg.is_empty() || raw_value.is_empty() || skip(&name) {
            out.push(Cow::Borrowed(seg));
            continue;
        }
        let value = decode(raw_value);
        let findings = walker.scanner.scan_field(&name, &value, false);
        if findings.is_empty() {
            out.push(Cow::Borrowed(seg));
            continue;
        }
        hits.extend(Hit::from_findings(&format!("{prefix}{name}"), &findings));
        if walker.redact {
            let redacted = redact::apply(&value, &findings);
            let encoded: String = form_urlencoded::byte_serialize(redacted.as_bytes()).collect();
            out.push(Cow::Owned(format!("{raw_name}={encoded}")));
            changed = true;
        } else {
            out.push(Cow::Borrowed(seg));
        }
    }
    FormScan {
        hits,
        rewritten: changed.then(|| out.join("&")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{allowlist::Allowlist, Scanner};
    use crate::path::SkipSet;

    fn token() -> String {
        ["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"].concat()
    }

    fn run(raw: &str, redact: bool, skip: &[&str]) -> FormScan {
        let s = Scanner::new(&[], &[], None, Allowlist::default(), "").unwrap();
        let skip_set = SkipSet::default();
        let w = Walker { scanner: &s, skip: &skip_set, decode_base64: false, max_decoded_bytes: 0, redact, llm_media: false };
        scan(raw, "query:", &w, |n| skip.contains(&n))
    }

    #[test]
    fn splits_path() {
        assert_eq!(split_path("/a/b?x=1&y"), ("/a/b", "x=1&y"));
        assert_eq!(split_path("/a"), ("/a", ""));
    }

    #[test]
    fn finds_decoded_values() {
        let raw = format!("a=1&t%6Fken={}&b=hello+world", token());
        let r = run(&raw, false, &[]);
        assert_eq!(r.hits.len(), 1);
        assert_eq!(r.hits[0].location, "query:token");
        assert!(r.rewritten.is_none());
    }

    #[test]
    fn redacts_only_the_hit_pair() {
        let raw = format!("a=%2Fx&token={}&flag", token());
        let r = run(&raw, true, &[]);
        assert_eq!(r.rewritten.as_deref(), Some("a=%2Fx&token=%5BREDACTED%3Agithub_token%5D&flag"));
    }

    #[test]
    fn skip_by_name() {
        assert!(run(&format!("key={}", token()), false, &["key"]).hits.is_empty());
    }
}
