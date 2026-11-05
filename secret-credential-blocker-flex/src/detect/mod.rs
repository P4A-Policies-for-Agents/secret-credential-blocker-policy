// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Secret detection engine.
//!
//! Pipeline per text: keyword prefilter → regex → validator → overlap
//! resolution by priority → allowlist. Findings carry the span and a
//! fingerprint; the raw value never leaves this module except through the
//! span the caller already holds.

pub mod allowlist;
pub mod builtin;
pub mod entropy;
pub mod keyname;

use anyhow::{anyhow, bail, Result};
use regex::Regex;

use crate::fingerprint::fingerprint;
use allowlist::Allowlist;
use entropy::EntropyDetector;

/// `(secret, whole text) -> keep?`
pub type Validator = fn(&str, &str) -> bool;

const CUSTOM_PRIORITY: u8 = 100;
const KEYNAME_PRIORITY: u8 = 20;
const ENTROPY_PRIORITY: u8 = 10;
const GENERIC: &str = "generic_secret_assignment";

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub kind: String,
    pub start: usize,
    pub end: usize,
    pub fingerprint: String,
}

struct Detector {
    kind: String,
    regex: Regex,
    keywords: Vec<String>,
    validator: Option<Validator>,
    priority: u8,
}

struct Candidate {
    kind: String,
    start: usize,
    end: usize,
    priority: u8,
}

pub struct Scanner {
    detectors: Vec<Detector>,
    entropy: Option<EntropyDetector>,
    allowlist: Allowlist,
    salt: String,
    keyname_enabled: bool,
    aws_secret_enabled: bool,
    gcp_sa_enabled: bool,
}

pub struct CustomSpec<'a> {
    pub name: &'a str,
    pub regex: &'a str,
}

impl Scanner {
    pub fn new(
        disabled: &[String],
        custom: &[CustomSpec<'_>],
        entropy: Option<EntropyDetector>,
        allowlist: Allowlist,
        salt: &str,
    ) -> Result<Self> {
        for d in disabled {
            if !builtin::BUILTIN_KINDS.contains(&d.as_str()) {
                bail!("disabledDetectors contains unknown detector '{d}'");
            }
        }
        let enabled = |kind: &str| !disabled.iter().any(|d| d == kind);
        let mut detectors = Vec::new();
        for spec in builtin::specs() {
            if !enabled(spec.kind) {
                continue;
            }
            detectors.push(Detector {
                kind: spec.kind.to_string(),
                regex: Regex::new(spec.pattern)
                    .map_err(|e| anyhow!("built-in detector {} failed to compile: {e}", spec.kind))?,
                keywords: spec.keywords.iter().map(|k| k.to_string()).collect(),
                validator: spec.validator,
                priority: spec.priority,
            });
        }
        for (i, c) in custom.iter().enumerate() {
            let name = c.name.trim();
            if name.is_empty()
                || name.len() > 64
                || !name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
            {
                bail!("customPatterns[{i}].name must be 1-64 letters, digits, '_' or '-'");
            }
            let normalized = normalize_double_escapes(c.regex);
            let processed = if normalized.starts_with('^') || normalized.ends_with('$') {
                normalized
            } else {
                format!(r"\b(?:{normalized})\b")
            };
            // The pattern text is not echoed: operators sometimes paste a literal secret.
            let regex = Regex::new(&processed)
                .map_err(|_| anyhow!("customPatterns[{i}] ('{name}') is not a valid regular expression"))?;
            detectors.push(Detector {
                kind: name.to_string(),
                regex,
                keywords: Vec::new(),
                validator: None,
                priority: CUSTOM_PRIORITY,
            });
        }
        Ok(Self {
            detectors,
            entropy,
            allowlist,
            salt: salt.to_string(),
            keyname_enabled: enabled(GENERIC),
            aws_secret_enabled: enabled("aws_secret_access_key"),
            gcp_sa_enabled: enabled("gcp_service_account"),
        })
    }

    /// Findings in free text, sorted by start, non-overlapping.
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        self.finish(text, self.candidates(text))
    }

    /// Findings in a named value (JSON member, form field, query parameter,
    /// header). Adds structural checks driven by the name: a sensitive name
    /// with a credential-looking value is reported even if no pattern matches.
    /// `service_account` marks the `private_key` of a GCP service-account object.
    pub fn scan_field(&self, name: &str, value: &str, service_account: bool) -> Vec<Finding> {
        let mut cands = self.candidates(value);
        if service_account && self.gcp_sa_enabled && name == "private_key" {
            for c in cands.iter_mut().filter(|c| c.kind == "private_key_pem") {
                c.kind = "gcp_service_account".to_string();
            }
        }
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            let start = value.len() - value.trim_start().len();
            let end = start + trimmed.len();
            if self.aws_secret_enabled
                && keyname::is_aws_secret_key(name)
                && trimmed.len() == 40
                && trimmed.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'+')
            {
                cands.push(Candidate {
                    kind: "aws_secret_access_key".to_string(),
                    start,
                    end,
                    priority: 90,
                });
            } else if self.keyname_enabled
                && keyname::is_sensitive_key(name)
                && keyname::looks_like_secret_value(trimmed)
            {
                cands.push(Candidate {
                    kind: GENERIC.to_string(),
                    start,
                    end,
                    priority: KEYNAME_PRIORITY,
                });
            }
        }
        self.finish(value, cands)
    }

    fn candidates(&self, text: &str) -> Vec<Candidate> {
        let mut out = Vec::new();
        if text.len() < 8 {
            return out;
        }
        let lower = text.to_ascii_lowercase();
        for d in &self.detectors {
            if !d.keywords.is_empty() && !d.keywords.iter().any(|k| lower.contains(k.as_str())) {
                continue;
            }
            for caps in d.regex.captures_iter(text) {
                let Some(m) = caps.name("secret").or_else(|| caps.get(0)) else {
                    continue;
                };
                if m.start() == m.end() {
                    continue;
                }
                if let Some(validate) = d.validator {
                    if !validate(m.as_str(), text) {
                        continue;
                    }
                }
                if is_redaction_marker(m.as_str()) {
                    continue;
                }
                out.push(Candidate {
                    kind: d.kind.clone(),
                    start: m.start(),
                    end: m.end(),
                    priority: d.priority,
                });
            }
        }
        if let Some(e) = &self.entropy {
            for (start, end) in e.find(text) {
                out.push(Candidate {
                    kind: entropy::KIND.to_string(),
                    start,
                    end,
                    priority: ENTROPY_PRIORITY,
                });
            }
        }
        out
    }

    /// Higher priority wins an overlap, then the longer span. Allowlisting a
    /// winner also suppresses the weaker detectors it overlapped.
    fn finish(&self, text: &str, mut cands: Vec<Candidate>) -> Vec<Finding> {
        cands.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then((b.end - b.start).cmp(&(a.end - a.start)))
                .then(a.start.cmp(&b.start))
        });
        let mut taken: Vec<Candidate> = Vec::new();
        for c in cands {
            if taken.iter().all(|t| c.end <= t.start || c.start >= t.end) {
                taken.push(c);
            }
        }
        taken.sort_by_key(|c| c.start);
        taken
            .into_iter()
            .filter_map(|c| {
                let value = &text[c.start..c.end];
                let fp = fingerprint(&self.salt, value);
                if self.allowlist.allows(value, &fp) {
                    return None;
                }
                Some(Finding {
                    kind: c.kind,
                    start: c.start,
                    end: c.end,
                    fingerprint: fp,
                })
            })
            .collect()
    }
}

/// Template placeholders and obvious dummies (`${X}`, `<your-key>`, `****`, `changeme`).
pub fn is_placeholder(v: &str) -> bool {
    let v = v.trim();
    if v.is_empty() {
        return true;
    }
    if (v.starts_with("${") || v.starts_with("{{") || v.starts_with('<') || v.starts_with("%("))
        || (v.starts_with('$') && v[1..].chars().all(|c| c.is_ascii_uppercase() || c == '_'))
        || is_redaction_marker(v)
    {
        return true;
    }
    let first = v.chars().next().unwrap_or(' ');
    if v.chars().all(|c| c == first) {
        return true;
    }
    let lower = v.to_ascii_lowercase();
    ["example", "changeme", "placeholder", "your_", "your-", "dummy", "redacted", "xxxxxx", "sample"]
        .iter()
        .any(|w| lower.contains(w))
}

fn is_redaction_marker(v: &str) -> bool {
    v.contains("[REDACTED:")
}

pub fn has_mixed_charset(v: &str) -> bool {
    v.bytes().any(|b| b.is_ascii_digit())
        && v.bytes().any(|b| b.is_ascii_uppercase())
        && v.bytes().any(|b| b.is_ascii_lowercase())
}

/// Some configuration paths double-escape regex metacharacters (`\\d`).
fn normalize_double_escapes(raw: &str) -> String {
    let mut s = raw.to_string();
    for c in ["d", "D", "w", "W", "s", "S", "b", "B", ".", "-"] {
        s = s.replace(&format!("\\\\{c}"), &format!("\\{c}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> Scanner {
        Scanner::new(&[], &[], None, Allowlist::default(), "").unwrap()
    }

    fn kinds(s: &Scanner, text: &str) -> Vec<String> {
        s.scan(text).into_iter().map(|f| f.kind).collect()
    }

    fn spans(text: &str, findings: &[Finding]) -> Vec<String> {
        findings.iter().map(|f| text[f.start..f.end].to_string()).collect()
    }

    // Test fixtures are assembled at runtime so that repository secret scanners
    // do not flag this file.
    fn cat(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn true_positives() {
        let s = scanner();
        let cases: Vec<(String, &str)> = vec![
            (cat(&["key AKIA", "IOSFODNN7EXAMPLQ end"]), "aws_access_key_id"),
            (cat(&["aws_secret_access_key = \"", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "\""]), "aws_secret_access_key"),
            (cat(&["AIza", "SyD-1234567890abcdefghijklmnopqrstu"]), "gcp_api_key"),
            (cat(&["DefaultEndpointsProtocol=https;AccountName=x;AccountKey=", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcd==", ";"]), "azure_storage_connection_string"),
            (cat(&["https://x.blob.core.windows.net/c?sv=2022&sig=", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456%3D"]), "azure_sas_token"),
            (cat(&["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"]), "github_token"),
            (cat(&["github_pat_", "11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz"]), "github_token"),
            (cat(&["glpat-", "abcdefghij1234567890"]), "gitlab_token"),
            (cat(&["xoxb-", "123456789012-1234567890123-abcdefghijklmnop"]), "slack_token"),
            (cat(&["https://hooks.slack.com/services/", "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"]), "slack_webhook"),
            (cat(&["sk_live_", "4eC39HqLyjWDarjtT1zdp7dc"]), "stripe_key"),
            (cat(&["sk-ant-api03-", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"]), "anthropic_api_key"),
            (cat(&["sk-proj-", "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cDe0fGh3i"]), "openai_api_key"),
            (cat(&["Bearer eyJhbGciOiJIUzI1NiJ9.", "eyJzdWIiOiIxMjM0NTY3ODkwIn0.", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"]), "jwt"),
            (cat(&["-----BEGIN RSA ", "PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"]), "private_key_pem"),
            (cat(&["-----BEGIN OPENSSH ", "PRIVATE KEY-----\nb3Blbg\n-----END OPENSSH PRIVATE KEY-----"]), "ssh_private_key"),
            (cat(&["postgres://admin:", "S3cretPass@db.internal:5432/app"]), "db_connection_string"),
            (cat(&["Server=tcp:db;User Id=sa;Password=", "Sup3rS3cret!;"]), "db_connection_string"),
            (cat(&["https://bob:", "hunter2pass@api.example.org/x"]), "basic_auth_url"),
            (cat(&["password=", "Tr0ub4dor&3"]), "generic_secret_assignment"),
        ];
        for (text, kind) in cases {
            assert_eq!(kinds(&s, &text), vec![kind.to_string()], "{text}");
        }
    }

    #[test]
    fn near_misses() {
        let s = scanner();
        for text in [
            "AKIA is a prefix",
            "pk_live_publishablekey1234567890",
            "sk-this-is-a-long-slug-name-not-a-key",
            "eyJub3RhIjoiand0In0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturesignature",
            "postgres://user:${DB_PASSWORD}@db:5432/app",
            "https://example.org/path?x=1",
            "password=changeme123",
            "the password is required",
            "commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
            "[REDACTED:github_token]",
        ] {
            assert!(kinds(&s, text).is_empty(), "{text} → {:?}", kinds(&s, text));
        }
    }

    #[test]
    fn secret_group_narrows_span() {
        let s = scanner();
        let text = cat(&["mongodb+srv://app:", "pa55Word9@cluster0.x.net/db"]);
        let f = s.scan(&text);
        assert_eq!(spans(&text, &f), vec!["pa55Word9"]);
    }

    #[test]
    fn anthropic_wins_over_openai() {
        let s = scanner();
        let text = cat(&["sk-ant-admin01-", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"]);
        assert_eq!(kinds(&s, &text), vec!["anthropic_api_key"]);
    }

    #[test]
    fn multiple_findings_sorted() {
        let s = scanner();
        let text = cat(&["a ghp_", "abcdefghijklmnopqrstuvwxyz0123456789 b AKIA", "IOSFODNN7EXAMPLQ"]);
        assert_eq!(kinds(&s, &text), vec!["github_token", "aws_access_key_id"]);
    }

    #[test]
    fn disabled_detectors() {
        let s = Scanner::new(&["github_token".into()], &[], None, Allowlist::default(), "").unwrap();
        assert!(kinds(&s, &cat(&["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"])).is_empty());
        assert!(Scanner::new(&["nope".into()], &[], None, Allowlist::default(), "").is_err());
    }

    #[test]
    fn custom_patterns_are_wrapped_and_validated() {
        let custom = [CustomSpec { name: "acme_key", regex: r"ACME-\\d{6}" }];
        let s = Scanner::new(&[], &custom, None, Allowlist::default(), "").unwrap();
        assert_eq!(kinds(&s, "use ACME-123456 now"), vec!["acme_key"]);
        assert!(kinds(&s, "XACME-123456").is_empty());
        let bad = [CustomSpec { name: "x", regex: "(LITERALVALUE" }];
        let err = Scanner::new(&[], &bad, None, Allowlist::default(), "").err().unwrap();
        assert!(!err.to_string().contains("LITERALVALUE"));
        let bad_name = [CustomSpec { name: "bad name", regex: "x" }];
        assert!(Scanner::new(&[], &bad_name, None, Allowlist::default(), "").is_err());
    }

    #[test]
    fn allowlist_suppresses_by_fingerprint() {
        let token = cat(&["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"]);
        let fp = fingerprint("", &token);
        let al = Allowlist::new(&[], &[fp], &[]).unwrap();
        let s = Scanner::new(&[], &[], None, al, "").unwrap();
        assert!(s.scan(&format!("x {token} y")).is_empty());
    }

    #[test]
    fn fingerprint_is_of_the_span() {
        let s = scanner();
        let token = cat(&["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"]);
        let f = s.scan(&format!("t={token}"));
        assert_eq!(f[0].fingerprint, fingerprint("", &token));
    }

    #[test]
    fn field_checks() {
        let s = scanner();
        assert_eq!(
            s.scan_field("password", "hunter22", false).iter().map(|f| f.kind.as_str()).collect::<Vec<_>>(),
            vec!["generic_secret_assignment"]
        );
        assert!(s.scan_field("password", "${PASSWORD}", false).is_empty());
        assert!(s.scan_field("username", "hunter22", false).is_empty());
        let aws = cat(&["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"]);
        assert_eq!(s.scan_field("SecretAccessKey", &aws, false)[0].kind, "aws_secret_access_key");
        let pem = cat(&["-----BEGIN ", "PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"]);
        assert_eq!(s.scan_field("private_key", &pem, true)[0].kind, "gcp_service_account");
        assert_eq!(s.scan_field("private_key", &pem, false)[0].kind, "private_key_pem");
    }

    #[test]
    fn entropy_is_lowest_priority() {
        let e = EntropyDetector::new(3.5, 20).unwrap();
        let s = Scanner::new(&[], &[], Some(e), Allowlist::default(), "").unwrap();
        let token = cat(&["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"]);
        assert_eq!(kinds(&s, &token), vec!["github_token"]);
        assert_eq!(kinds(&s, "Zx9Qp2Lm7Rt4Vb8Nc1Kd6Hs3Jf5Wg0Ya"), vec!["high_entropy_string"]);
    }

    #[test]
    fn serialized_service_account() {
        let s = scanner();
        let text = cat(&[
            r#"{"type":"service_account","private_key":"-----BEGIN "#,
            r#"PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"}"#,
        ]);
        assert_eq!(kinds(&s, &text), vec!["gcp_service_account"]);
    }
}
