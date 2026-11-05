// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Validated runtime settings built once at configure time.

use anyhow::{anyhow, bail, Result};

use crate::detect::{allowlist::Allowlist, entropy::EntropyDetector, CustomSpec, Scanner};
use crate::generated::config::{AllowlistConfig, Config};
use crate::path::SkipSet;
use crate::protocol::Mode;
use crate::walk::Walker;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Block,
    Redact,
    Monitor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseMode {
    Stream,
    Buffer,
    Monitor,
}

/// Headers that carry the caller's own credentials; never scanned.
pub const NEVER_SCANNED_HEADERS: &[&str] = &["authorization", "cookie", "proxy-authorization"];

/// Members of an A2A push-notification config the agent needs verbatim.
const PUSH_CREDENTIAL_PATHS: &[&str] = &["$..authentication", "$..token", "$..credentials"];

pub struct Settings {
    pub action: Action,
    pub mode: Mode,
    pub scanner: Scanner,
    pub skip: SkipSet,
    /// `skip` plus the webhook credentials of A2A push-notification configs.
    pub push_skip: SkipSet,
    pub headers: Vec<String>,
    pub query_params: bool,
    pub rest_body: bool,
    pub multipart: bool,
    pub decode_base64: bool,
    pub max_decoded_bytes: usize,
    pub response: Option<ResponseSettings>,
    pub max_body_bytes: usize,
    pub fail_closed: bool,
    pub error_detail: bool,
    pub error_domain: String,
}

pub struct ResponseSettings {
    pub action: Action,
    pub sse_mode: SseMode,
}

fn action(raw: Option<&str>, field: &str) -> Result<Action> {
    Ok(match raw.unwrap_or("block") {
        "block" => Action::Block,
        "redact" => Action::Redact,
        "monitor" => Action::Monitor,
        other => bail!("{field} must be block, redact or monitor (got '{other}')"),
    })
}

fn bounded(raw: Option<i64>, default: i64, min: i64, max: i64, field: &str) -> Result<usize> {
    let v = raw.unwrap_or(default);
    if !(min..=max).contains(&v) {
        bail!("{field} must be between {min} and {max} (got {v})");
    }
    usize::try_from(v).map_err(|_| anyhow!("{field} is out of range"))
}

impl Settings {
    pub fn from_config(c: &Config) -> Result<Self> {
        let action = action(c.action.as_deref(), "action")?;
        let mode = match c.protocol.as_deref().unwrap_or("auto") {
            "auto" => Mode::Auto,
            "rest" => Mode::Rest,
            "mcp" => Mode::Mcp,
            "a2a" => Mode::A2a,
            other => bail!("protocol must be auto, rest, mcp or a2a (got '{other}')"),
        };
        let entropy = match &c.entropy {
            Some(e) if e.enabled.unwrap_or(false) => {
                let min_length = bounded(e.min_length, 24, 8, 1024, "entropy.minLength")?;
                Some(EntropyDetector::new(e.threshold.unwrap_or(4.5), min_length)?)
            }
            _ => None,
        };
        let al = c.allowlist.as_ref();
        let list = |f: fn(&AllowlistConfig) -> &Option<Vec<String>>| al.and_then(|a| f(a).clone()).unwrap_or_default();
        let skip_paths = list(|a| &a.skip_paths);
        let allowlist = Allowlist::new(&list(|a| &a.values), &list(|a| &a.fingerprints), &list(|a| &a.patterns))?;
        let skip = SkipSet::parse(&skip_paths)?;
        let mut push_paths = skip_paths;
        push_paths.extend(PUSH_CREDENTIAL_PATHS.iter().map(|p| p.to_string()));
        let push_skip = SkipSet::parse(&push_paths)?;
        let custom: Vec<CustomSpec> = c
            .custom_patterns
            .iter()
            .flatten()
            .map(|p| CustomSpec { name: &p.name, regex: &p.regex })
            .collect();
        let scanner = Scanner::new(
            c.disabled_detectors.as_deref().unwrap_or_default(),
            &custom,
            entropy,
            allowlist,
            c.fingerprint_salt.as_deref().unwrap_or(""),
        )?;
        let s = c.scan.as_ref();
        let headers = s
            .and_then(|s| s.headers.as_ref())
            .into_iter()
            .flatten()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty() && !NEVER_SCANNED_HEADERS.contains(&h.as_str()))
            .collect();
        let response = if let Some(r) = c.response_scanning.as_ref().filter(|r| r.enabled.unwrap_or(false)) {
            let raction = match r.action.as_deref().unwrap_or("inherit") {
                "inherit" => action,
                other => self::action(Some(other), "responseScanning.action")?,
            };
            let sse_mode = match r.sse_mode.as_deref().unwrap_or("stream") {
                "stream" => SseMode::Stream,
                "buffer" => SseMode::Buffer,
                "monitor" => SseMode::Monitor,
                other => bail!("responseScanning.sseMode must be stream, buffer or monitor (got '{other}')"),
            };
            Some(ResponseSettings { action: raction, sse_mode })
        } else {
            None
        };
        let oversize = c.oversize_behavior.as_deref().unwrap_or("failOpen");
        let fail_closed = match oversize {
            "failOpen" => false,
            "failClosed" => true,
            other => bail!("oversizeBehavior must be failOpen or failClosed (got '{other}')"),
        };
        Ok(Self {
            action,
            mode,
            scanner,
            skip,
            push_skip,
            headers,
            query_params: s.and_then(|s| s.query_params).unwrap_or(true),
            rest_body: s.and_then(|s| s.rest_body).unwrap_or(true),
            multipart: s.and_then(|s| s.multipart).unwrap_or(true),
            decode_base64: s.and_then(|s| s.decode_base_64_parts).unwrap_or(true),
            max_decoded_bytes: bounded(
                s.and_then(|s| s.max_decoded_bytes),
                262_144,
                0,
                4_194_304,
                "scan.maxDecodedBytes",
            )?,
            response,
            max_body_bytes: bounded(c.max_body_bytes, 1_048_576, 1024, 16_777_216, "maxBodyBytes")?,
            fail_closed,
            error_detail: c.error_detail.unwrap_or(true),
            error_domain: c
                .error_domain
                .clone()
                .filter(|d| !d.trim().is_empty())
                .unwrap_or_else(|| "p4a.ai".to_string()),
        })
    }

    pub fn walker(&self, redact: bool, push_config: bool) -> Walker<'_> {
        Walker {
            scanner: &self.scanner,
            skip: if push_config { &self.push_skip } else { &self.skip },
            decode_base64: self.decode_base64,
            max_decoded_bytes: self.max_decoded_bytes,
            redact,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(v: serde_json::Value) -> Result<Settings> {
        Settings::from_config(&serde_json::from_value(v).unwrap())
    }

    #[test]
    fn defaults() {
        let s = parse(serde_json::json!({})).unwrap();
        assert_eq!(s.action, Action::Block);
        assert_eq!(s.mode, Mode::Auto);
        assert!(s.query_params && s.rest_body && s.multipart && s.decode_base64);
        assert!(s.response.is_none());
        assert!(!s.fail_closed);
        assert_eq!(s.max_body_bytes, 1_048_576);
        assert_eq!(s.error_domain, "p4a.ai");
    }

    #[test]
    fn camel_case_and_inherit() {
        let s = parse(serde_json::json!({
            "action": "redact",
            "responseScanning": {"enabled": true, "action": "inherit", "sseMode": "buffer"},
            "scan": {"headers": ["X-Debug", "Authorization", ""], "queryParams": false},
            "oversizeBehavior": "failClosed"
        }))
        .unwrap();
        let r = s.response.unwrap();
        assert_eq!((r.action, r.sse_mode), (Action::Redact, SseMode::Buffer));
        assert_eq!(s.headers, vec!["x-debug"]);
        assert!(!s.query_params && s.fail_closed);
    }

    #[test]
    fn rejects_invalid() {
        for bad in [
            serde_json::json!({"action": "drop"}),
            serde_json::json!({"protocol": "grpc"}),
            serde_json::json!({"maxBodyBytes": 1}),
            serde_json::json!({"allowlist": {"skipPaths": ["nope"]}}),
            serde_json::json!({"customPatterns": [{"name": "x", "regex": "("}]}),
            serde_json::json!({"entropy": {"enabled": true, "minLength": 2}}),
        ] {
            assert!(parse(bad.clone()).is_err(), "{bad}");
        }
    }
}
