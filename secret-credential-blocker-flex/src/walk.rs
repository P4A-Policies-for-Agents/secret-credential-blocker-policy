// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Recursive scan of a JSON document, with optional in-place redaction.

use base64::Engine;
use serde_json::Value;

use crate::detect::{Finding, Scanner};
use crate::path::{JsonPath, SkipSet};
use crate::redact;

/// One detected secret, as reported to logs and (without the fingerprint) to clients.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub kind: String,
    pub location: String,
    pub fingerprint: String,
}

impl Hit {
    pub fn from_findings(location: &str, findings: &[Finding]) -> Vec<Hit> {
        findings
            .iter()
            .map(|f| Hit {
                kind: f.kind.clone(),
                location: location.to_string(),
                fingerprint: f.fingerprint.clone(),
            })
            .collect()
    }
}

/// Members whose string value is base64-encoded content: A2A v0.3
/// `file.bytes`, A2A v1 `raw`, MCP resource `blob`.
const BASE64_KEYS: &[&str] = &["bytes", "raw", "blob"];

/// LLM media members: Anthropic `source.data`, Gemini `inlineData.data`,
/// OpenAI `input_audio.data` / `file.file_data`. Data URIs are handled too.
const LLM_MEDIA_KEYS: &[&str] = &["data", "file_data"];

/// Base64 payloads shorter than this are scanned as plain text.
const MIN_MEDIA_LEN: usize = 64;

fn looks_base64(s: &str) -> bool {
    s.len() >= MIN_MEDIA_LEN
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'\n' | b'\r'))
}

/// `(prefix through ";base64,", payload)` of a base64 data URI.
fn split_data_uri(s: &str) -> Option<(&str, &str)> {
    if !s.starts_with("data:") {
        return None;
    }
    let i = s.find(";base64,")? + ";base64,".len();
    Some((&s[..i], &s[i..]))
}

pub struct Walker<'a> {
    pub scanner: &'a Scanner,
    pub skip: &'a SkipSet,
    pub decode_base64: bool,
    pub max_decoded_bytes: usize,
    pub redact: bool,
    /// LLM traffic: base64 media is decoded when it is text and never
    /// scanned as raw base64 otherwise.
    pub llm_media: bool,
}

impl Walker<'_> {
    /// Scans the subtree at `root` (a path into `doc`; empty = whole document).
    /// Locations are rendered from the document root.
    pub fn walk_at(&self, doc: &mut Value, root: &[&str]) -> Vec<Hit> {
        let mut path = JsonPath::root();
        let mut node = doc;
        for key in root {
            let Some(next) = node.get_mut(*key) else {
                return Vec::new();
            };
            path.push_key(key);
            node = next;
        }
        self.walk_in(node, &mut path)
    }

    /// Scans `node`, located at `path` in its document.
    pub fn walk_in(&self, node: &mut Value, path: &mut JsonPath) -> Vec<Hit> {
        let mut hits = Vec::new();
        self.walk(node, path, None, false, &mut hits);
        hits
    }

    fn walk(
        &self,
        value: &mut Value,
        path: &mut JsonPath,
        key: Option<&str>,
        in_service_account: bool,
        hits: &mut Vec<Hit>,
    ) {
        if self.skip.json(path) {
            return;
        }
        match value {
            Value::Object(map) => {
                let sa = map.get("type").and_then(Value::as_str) == Some("service_account");
                for (k, v) in map.iter_mut() {
                    path.push_key(k);
                    self.walk(v, path, Some(k.as_str()), sa, hits);
                    path.pop();
                }
            }
            Value::Array(items) => {
                for (i, v) in items.iter_mut().enumerate() {
                    path.push_index(i);
                    self.walk(v, path, key, false, hits);
                    path.pop();
                }
            }
            Value::String(s) => {
                let key = key.unwrap_or("");
                if self.decode_base64 && BASE64_KEYS.contains(&key) {
                    if let Some(rewritten) = self.scan_base64(s, path, hits) {
                        *s = rewritten;
                    }
                    return;
                }
                if self.llm_media {
                    if let Some((prefix, payload)) = split_data_uri(s) {
                        if let Some(rewritten) = self.scan_base64(payload, path, hits) {
                            *s = format!("{prefix}{rewritten}");
                        }
                        return;
                    }
                    if LLM_MEDIA_KEYS.contains(&key) && looks_base64(s) {
                        if let Some(rewritten) = self.scan_base64(s, path, hits) {
                            *s = rewritten;
                        }
                        return;
                    }
                }
                let findings = self.scanner.scan_field(key, s, in_service_account);
                if findings.is_empty() {
                    return;
                }
                hits.extend(Hit::from_findings(&path.render(), &findings));
                if self.redact {
                    *s = redact::apply(s, &findings);
                }
            }
            _ => {}
        }
    }

    /// Decodes, scans and (when redacting) re-encodes a base64 member. Binary
    /// or oversized content is not scanned. Returns the replacement string.
    fn scan_base64(&self, encoded: &str, path: &JsonPath, hits: &mut Vec<Hit>) -> Option<String> {
        if !self.decode_base64 || encoded.len() / 4 * 3 > self.max_decoded_bytes {
            return None;
        }
        let engine = base64::engine::general_purpose::STANDARD;
        let compact: String = encoded.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let decoded = engine.decode(compact).ok()?;
        let text = String::from_utf8(decoded).ok()?;
        let findings = self.scanner.scan(&text);
        if findings.is_empty() {
            return None;
        }
        hits.extend(Hit::from_findings(&format!("{}(base64)", path.render()), &findings));
        self.redact
            .then(|| engine.encode(redact::apply(&text, &findings)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::allowlist::Allowlist;
    use serde_json::json;

    fn token() -> String {
        ["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"].concat()
    }

    fn scanner() -> Scanner {
        Scanner::new(&[], &[], None, Allowlist::default(), "").unwrap()
    }

    fn walker<'a>(s: &'a Scanner, skip: &'a SkipSet, redact: bool) -> Walker<'a> {
        Walker {
            scanner: s,
            skip,
            decode_base64: true,
            max_decoded_bytes: 1024,
            redact,
            llm_media: false,
        }
    }

    #[test]
    fn finds_nested_secrets_with_paths() {
        let s = scanner();
        let skip = SkipSet::default();
        let mut doc = json!({"params": {"arguments": {"q": format!("use {}", token()), "list": ["ok", {"password": "hunter22"}]}}});
        let hits = walker(&s, &skip, false).walk_at(&mut doc, &[]);
        let locs: Vec<_> = hits.iter().map(|h| (h.kind.as_str(), h.location.as_str())).collect();
        assert_eq!(
            locs,
            vec![
                ("github_token", "$.params.arguments.q"),
                ("generic_secret_assignment", "$.params.arguments.list[1].password"),
            ]
        );
    }

    #[test]
    fn root_limits_scope_and_skip_paths_apply() {
        let s = scanner();
        let skip = SkipSet::parse(&["$.params.arguments.skipme".into()]).unwrap();
        let mut doc = json!({"method": token(), "params": {"arguments": {"skipme": token(), "x": token()}}});
        let hits = walker(&s, &skip, false).walk_at(&mut doc, &["params", "arguments"]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].location, "$.params.arguments.x");
        assert!(walker(&s, &skip, false).walk_at(&mut doc, &["missing"]).is_empty());
    }

    #[test]
    fn redacts_in_place() {
        let s = scanner();
        let skip = SkipSet::default();
        let mut doc = json!({"text": format!("a {} b", token())});
        walker(&s, &skip, true).walk_at(&mut doc, &[]);
        assert_eq!(doc, json!({"text": "a [REDACTED:github_token] b"}));
    }

    #[test]
    fn base64_parts_are_decoded_and_reencoded() {
        let s = scanner();
        let skip = SkipSet::default();
        let engine = base64::engine::general_purpose::STANDARD;
        let mut doc = json!({"file": {"bytes": engine.encode(format!("cfg {}", token()))}, "blob": engine.encode([0xff, 0xfe, 0x00])});
        let hits = walker(&s, &skip, true).walk_at(&mut doc, &[]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].location, "$.file.bytes(base64)");
        let out = engine.decode(doc["file"]["bytes"].as_str().unwrap()).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "cfg [REDACTED:github_token]");
    }

    #[test]
    fn oversized_base64_is_not_decoded() {
        let s = scanner();
        let skip = SkipSet::default();
        let engine = base64::engine::general_purpose::STANDARD;
        let mut doc = json!({"raw": engine.encode(format!("{}{}", "x".repeat(2000), token()))});
        assert!(walker(&s, &skip, false).walk_at(&mut doc, &[]).is_empty());
    }

    #[test]
    fn service_account_object() {
        let s = scanner();
        let skip = SkipSet::default();
        let pem = ["-----BEGIN ", "PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"].concat();
        let mut doc = json!({"creds": {"type": "service_account", "private_key": pem}});
        let hits = walker(&s, &skip, false).walk_at(&mut doc, &[]);
        assert_eq!(hits[0].kind, "gcp_service_account");
        assert_eq!(hits[0].location, "$.creds.private_key");
    }
}
