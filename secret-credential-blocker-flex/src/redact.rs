// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Replaces detected spans with `[REDACTED:<detector>]`.

use crate::detect::Finding;

pub fn marker(kind: &str) -> String {
    format!("[REDACTED:{kind}]")
}

/// Rewrites `text`, replacing each finding's span. `findings` must be
/// non-overlapping and sorted by start, as returned by `Scanner::scan`.
pub fn apply(text: &str, findings: &[Finding]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for f in findings {
        if f.start < cursor || f.end > text.len() {
            continue;
        }
        out.push_str(&text[cursor..f.start]);
        out.push_str(&marker(&f.kind));
        cursor = f.end;
    }
    out.push_str(&text[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(kind: &str, start: usize, end: usize) -> Finding {
        Finding {
            kind: kind.to_string(),
            start,
            end,
            fingerprint: String::new(),
        }
    }

    #[test]
    fn replaces_spans_in_order() {
        let text = "a=SECRET1 b=SECRET2 c";
        let out = apply(text, &[f("x", 2, 9), f("y", 12, 19)]);
        assert_eq!(out, "a=[REDACTED:x] b=[REDACTED:y] c");
    }

    #[test]
    fn no_findings_is_identity() {
        assert_eq!(apply("plain", &[]), "plain");
    }
}
