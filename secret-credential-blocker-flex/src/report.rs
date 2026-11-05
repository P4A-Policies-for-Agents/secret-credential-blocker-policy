// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Logging of findings. Only the detector kind, location and fingerprint are
//! ever logged — never the value.

use pdk::logger;

use crate::errors::Direction;
use crate::settings::Action;
use crate::walk::Hit;

fn dir_label(dir: Direction) -> &'static str {
    match dir {
        Direction::Request => "request",
        Direction::Response => "response",
    }
}

fn action_label(a: Action) -> &'static str {
    match a {
        Action::Block => "block",
        Action::Redact => "redact",
        Action::Monitor => "monitor",
    }
}

/// One line per finding.
pub fn format_hits(dir: Direction, protocol: &str, op: Option<&str>, action: Action, hits: &[Hit]) -> Vec<String> {
    hits.iter()
        .map(|h| {
            format!(
                "[secret-blocker] {} {} op={} action={} detector={} location={} fingerprint={}",
                dir_label(dir),
                protocol,
                op.unwrap_or("-"),
                action_label(action),
                h.kind,
                h.location,
                h.fingerprint
            )
        })
        .collect()
}

pub fn log_hits(dir: Direction, protocol: &str, op: Option<&str>, action: Action, hits: &[Hit]) {
    for line in format_hits(dir, protocol, op, action, hits) {
        logger::warn!("{line}");
    }
}

pub fn log_unscannable(dir: Direction, why: &str, fail_closed: bool) {
    let outcome = if fail_closed { "blocked (failClosed)" } else { "passed unscanned (failOpen)" };
    logger::warn!("[secret-blocker] {} not scanned: {why}; {outcome}", dir_label(dir));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_carry_no_value() {
        let hits = vec![Hit { kind: "jwt".into(), location: "header:x-debug".into(), fingerprint: "sha256:abcdefabcdef".into() }];
        let lines = format_hits(Direction::Request, "rest", None, Action::Monitor, &hits);
        assert_eq!(
            lines,
            vec!["[secret-blocker] request rest op=- action=monitor detector=jwt location=header:x-debug fingerprint=sha256:abcdefabcdef"]
        );
    }
}
